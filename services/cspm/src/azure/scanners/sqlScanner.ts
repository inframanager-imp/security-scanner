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
          findings.push(this.finding(
            'SQL Server has public network access enabled',
            `SQL Server "${serverName}" has publicNetworkAccess set to "Enabled". The server endpoint is reachable from the public internet, relying solely on firewall rules and authentication as defence.`,
            'HIGH',
            { server: serverName, resourceGroup: rg },
            'Set publicNetworkAccess to "Disabled" and use Private Endpoint for all database connectivity. Migrate applications to use the private DNS zone.',
            ['sql', 'network', 'public-access'],
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
          findings.push(this.finding(
            'SQL Server firewall allows access from all IP addresses',
            `SQL Server "${serverName}" has a firewall rule allowing 0.0.0.0–255.255.255.255. This exposes the server to the entire internet.`,
            'CRITICAL',
            { server: serverName, rules: allowAll.map(r => r.name), resourceGroup: rg },
            'Remove the overly permissive firewall rule. Restrict access to specific known IP ranges or use Private Endpoint.',
            ['sql', 'firewall', 'network'],
          ));
        }

        // ── Azure AD admin not configured ────────────────────────────────
        try {
          const admins: any[] = [];
          for await (const a of sqlClient.serverAzureADAdministrators.listByServer(rg, serverName)) {
            admins.push(a);
          }
          if (admins.length === 0) {
            findings.push(this.finding(
              'SQL Server has no Azure AD administrator configured',
              `SQL Server "${serverName}" does not have an Azure Active Directory administrator. This forces SQL authentication which lacks MFA and conditional access support.`,
              'HIGH',
              { server: serverName, resourceGroup: rg },
              'Configure an Azure AD administrator for all SQL Servers. Disable SQL authentication for privileged access.',
              ['sql', 'authentication', 'aad'],
            ));
          }
        } catch { /* skip */ }

        // ── Auditing ─────────────────────────────────────────────────────
        try {
          const auditPolicy = await sqlClient.serverBlobAuditingPolicies.get(rg, serverName);
          if (auditPolicy.state !== 'Enabled') {
            findings.push(this.finding(
              'SQL Server auditing is disabled',
              `SQL Server "${serverName}" does not have auditing enabled. Without auditing, malicious queries, unauthorized access, and data exfiltration cannot be detected.`,
              'HIGH',
              { server: serverName, resourceGroup: rg },
              'Enable auditing for all SQL Servers and configure a log retention period of at least 90 days.',
              ['sql', 'auditing', 'logging'],
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
              findings.push(this.finding(
                'SQL Database Transparent Data Encryption (TDE) disabled',
                `Database "${dbName}" on server "${serverName}" does not have TDE enabled. Data at rest is unencrypted.`,
                'HIGH',
                { server: serverName, database: dbName, resourceGroup: rg },
                'Enable Transparent Data Encryption on all SQL databases.',
                ['sql', 'tde', 'encryption'],
              ));
            }
          } catch { /* skip */ }

          // Threat detection
          try {
            const td = await sqlClient.databaseSecurityAlertPolicies.get(rg, serverName, dbName, 'Default');
            if (td.state !== 'Enabled') {
              findings.push(this.finding(
                'SQL Database threat detection (Advanced Threat Protection) disabled',
                `Database "${dbName}" on server "${serverName}" does not have Advanced Threat Protection enabled. SQL injection, anomalous access patterns, and brute-force will not be detected.`,
                'MEDIUM',
                { server: serverName, database: dbName, resourceGroup: rg },
                'Enable Microsoft Defender for SQL on the server level, which covers all databases.',
                ['sql', 'threat-detection'],
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
