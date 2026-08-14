// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const RECOMMENDED_MIN_TLS_VERSIONS = ['1.2', '1.3'];

export class AzureSQLScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-SQL');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const sqlClient = this.client.sql();

    try {
      const servers: any[] = [];
      for await (const s of sqlClient.servers.list()) servers.push(s);

      for (const server of servers) {
        const serverName = server.name ?? 'unknown';
        const rg = server.id?.split('/')[4] ?? 'unknown';

        // ── Public network access ─────────────────────────────────────────
        if (server.publicNetworkAccess === 'Enabled') {
          findings.push(this.emit(
            'azure_sql_public_network_access_disabled',
            { server: serverName, resourceGroup: rg },
            { message: `SQL Server "${serverName}" has publicNetworkAccess set to "Enabled". The server endpoint is reachable from the public internet, relying solely on firewall rules and authentication as defence.` },
          ));
        }

        // ── Firewall: allow-all rule ──────────────────────────────────────
        const firewallRules: any[] = [];
        for await (const rule of sqlClient.firewallRules.listByServer(rg, serverName)) {
          firewallRules.push(rule);
        }
        const allowAll = firewallRules.filter(r =>
          r.startIpAddress === '0.0.0.0' && r.endIpAddress === '255.255.255.255',
        );
        if (allowAll.length > 0) {
          findings.push(this.emit(
            'azure_sql_firewall_no_allow_all_rule',
            { server: serverName, rules: allowAll.map(r => r.name), resourceGroup: rg },
            { message: `SQL Server "${serverName}" has a firewall rule allowing 0.0.0.0–255.255.255.255. This exposes the server to the entire internet.` },
          ));
        }

        // ── Minimum TLS version (sqlserver_recommended_minimal_tls_version) ─
        const minimalTlsVersion: string = server.minimalTlsVersion ?? '';
        if (!RECOMMENDED_MIN_TLS_VERSIONS.includes(minimalTlsVersion)) {
          findings.push(this.emit(
            'sqlserver_recommended_minimal_tls_version',
            { server: serverName, resourceGroup: rg, minimalTlsVersion: minimalTlsVersion || 'unset' },
            { message: `SQL Server "${serverName}" is using TLS version "${minimalTlsVersion || 'unset'}" as the minimal accepted version, which is not recommended. Use 1.2 or 1.3.` },
          ));
        }

        // ── Azure AD admin not configured ────────────────────────────────
        try {
          const admins: any[] = [];
          for await (const a of sqlClient.serverAzureADAdministrators.listByServer(rg, serverName)) {
            admins.push(a);
          }
          if (admins.length === 0) {
            findings.push(this.emit(
              'azure_sql_azuread_admin_configured',
              { server: serverName, resourceGroup: rg },
              { message: `SQL Server "${serverName}" does not have an Azure Active Directory administrator. This forces SQL authentication which lacks MFA and conditional access support.` },
            ));
          }
        } catch { /* skip */ }

        // ── Auditing ─────────────────────────────────────────────────────
        try {
          const auditPolicy = await sqlClient.serverBlobAuditingPolicies.get(rg, serverName);
          if (auditPolicy.state !== 'Enabled') {
            findings.push(this.emit(
              'azure_sql_auditing_enabled',
              { server: serverName, resourceGroup: rg },
              { message: `SQL Server "${serverName}" does not have auditing enabled. Without auditing, malicious queries, unauthorized access, and data exfiltration cannot be detected.` },
            ));
          } else {
            // sqlserver_auditing_retention_90_days — only meaningful once auditing is enabled
            const retentionDays = auditPolicy.retentionDays ?? 0;
            if (retentionDays <= 90) {
              findings.push(this.emit(
                'sqlserver_auditing_retention_90_days',
                { server: serverName, resourceGroup: rg, retentionDays },
                { message: `SQL Server "${serverName}" has auditing enabled but with a retention period of ${retentionDays} days, which does not exceed the recommended 90-day minimum.` },
              ));
            }
          }
        } catch { /* skip */ }

        // ── Encryption protector / TDE with CMK (sqlserver_tde_encrypted_with_cmk) ─
        let usesCmkProtector = false;
        try {
          const protector = await sqlClient.encryptionProtectors.get(rg, serverName, 'current');
          usesCmkProtector = protector.serverKeyType === 'AzureKeyVault';
        } catch { /* server may not expose an encryption protector */ }

        // ── Vulnerability Assessment ─────────────────────────────────────
        try {
          const va = await sqlClient.serverVulnerabilityAssessments.get(rg, serverName, 'default');
          const vaEnabled = Boolean(va.storageContainerPath);

          if (!vaEnabled) {
            findings.push(this.emit(
              'sqlserver_vulnerability_assessment_enabled',
              { server: serverName, resourceGroup: rg },
              { message: `SQL Server "${serverName}" has vulnerability assessment disabled (no storage container configured for scan results).` },
            ));
          } else {
            const recurring = va.recurringScans;
            if (!recurring?.isEnabled) {
              findings.push(this.emit(
                'sqlserver_va_periodic_recurring_scans_enabled',
                { server: serverName, resourceGroup: rg },
                { message: `SQL Server "${serverName}" has vulnerability assessment enabled but periodic recurring scans are not turned on.` },
              ));
            }
            if (!recurring?.emailSubscriptionAdmins) {
              findings.push(this.emit(
                'sqlserver_va_emails_notifications_admins_enabled',
                { server: serverName, resourceGroup: rg },
                { message: `SQL Server "${serverName}" has vulnerability assessment enabled but recurring-scan email notifications to subscription admins are not configured.` },
              ));
            }
            const hasReportRecipients = Boolean(recurring?.emailSubscriptionAdmins) || (recurring?.emails?.length ?? 0) > 0;
            if (!hasReportRecipients) {
              findings.push(this.emit(
                'sqlserver_va_scan_reports_configured',
                { server: serverName, resourceGroup: rg },
                { message: `SQL Server "${serverName}" has vulnerability assessment enabled but no scan report recipients (subscription admins or explicit emails) are configured.` },
              ));
            }
          }
        } catch { /* vulnerability assessment not configured or not accessible */ }

        // ── Per-database checks ──────────────────────────────────────────
        const databases: any[] = [];
        for await (const db of sqlClient.databases.listByServer(rg, serverName)) databases.push(db);

        const nonMasterDatabases = databases.filter(db => db.name !== 'master');
        let anyTdeDisabled = false;

        for (const db of nonMasterDatabases) {
          const dbName = db.name ?? 'unknown';

          // TDE
          try {
            const tde = await sqlClient.transparentDataEncryptions.get(rg, serverName, dbName, 'current');
            if (tde.state !== 'Enabled') {
              anyTdeDisabled = true;
              findings.push(this.emit(
                'azure_sql_database_tde_enabled',
                { server: serverName, database: dbName, resourceGroup: rg },
                { message: `Database "${dbName}" on server "${serverName}" does not have TDE enabled. Data at rest is unencrypted.` },
              ));
            }
          } catch { /* skip */ }

          // Threat detection
          try {
            const td = await sqlClient.databaseSecurityAlertPolicies.get(rg, serverName, dbName, 'Default');
            if (td.state !== 'Enabled') {
              findings.push(this.emit(
                'azure_sql_database_threat_detection_enabled',
                { server: serverName, database: dbName, resourceGroup: rg },
                { message: `Database "${dbName}" on server "${serverName}" does not have Advanced Threat Protection enabled. SQL injection, anomalous access patterns, and brute-force will not be detected.` },
              ));
            }
          } catch { /* skip */ }
        }

        // sqlserver_tde_encrypted_with_cmk — server-level rollup: CMK protector
        // must be in use AND every non-master database must have TDE enabled.
        if (nonMasterDatabases.length > 0 && (!usesCmkProtector || anyTdeDisabled)) {
          findings.push(this.emit(
            'sqlserver_tde_encrypted_with_cmk',
            { server: serverName, resourceGroup: rg, usesCmkProtector, anyTdeDisabled },
            {
              message: !usesCmkProtector
                ? `SQL Server "${serverName}" TDE protector does not use a customer-managed key (Key Vault). Databases are encrypted with a service-managed key instead.`
                : `SQL Server "${serverName}" uses a customer-managed TDE protector, but at least one database has TDE disabled.`,
            },
          ));
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure SQL scan error',
        `Could not complete SQL scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has SQL Server Contributor or Reader permissions.',
      ));
    }

    return findings;
  }
}
