import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

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
          }
        } catch { /* skip */ }

        // ── Per-database checks ──────────────────────────────────────────
        const databases: any[] = [];
        for await (const db of sqlClient.databases.listByServer(rg, serverName)) databases.push(db);

        for (const db of databases) {
          if (db.name === 'master') continue;
          const dbName = db.name ?? 'unknown';

          // TDE
          try {
            const tde = await sqlClient.transparentDataEncryptions.get(rg, serverName, dbName, 'current');
            if (tde.state !== 'Enabled') {
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
