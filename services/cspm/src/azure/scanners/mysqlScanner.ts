import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureMySQLScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-MySQL');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const mysqlClient = this.client.mysql();

      const servers: any[] = [];
      for await (const srv of mysqlClient.servers.list()) servers.push(srv);

      if (servers.length === 0) return findings;

      for (const server of servers) {
        const name = server.name ?? 'unknown';
        const rg   = server.id?.split('/')[4] ?? 'unknown';
        const version = server.version ?? 'unknown';

        // 1. Public network access enabled
        const publicAccess = server.network?.publicNetworkAccess ?? 'Enabled';
        if (publicAccess === 'Enabled') {
          findings.push(this.finding(
            'MySQL Flexible Server has public network access enabled',
            `MySQL Flexible Server "${name}" is accessible from the public internet. This increases exposure to brute-force, credential stuffing, and SQL injection attacks.`,
            'HIGH',
            { server: name, resourceGroup: rg, version },
            'Set network.publicNetworkAccess to "Disabled" and configure VNet-integrated private access to restrict connectivity to trusted internal networks.',
            ['mysql', 'network', 'public-access'],
          ));
        }

        // 2. SSL enforcement — require_secure_transport
        try {
          const sslConfig = await mysqlClient.configurations.get(rg, name, 'require_secure_transport');
          if (sslConfig.value !== 'ON') {
            findings.push(this.finding(
              'MySQL Flexible Server does not require SSL connections',
              `MySQL Flexible Server "${name}" has require_secure_transport set to "${sslConfig.value}". Client connections may transmit credentials and query data in plaintext.`,
              'CRITICAL',
              { server: name, resourceGroup: rg, requireSecureTransport: sslConfig.value },
              'Set the require_secure_transport server parameter to "ON". Update all application connection strings to use SSL mode "REQUIRED" or "VERIFY_CA".',
              ['mysql', 'encryption-in-transit', 'ssl'],
            ));
          }
        } catch { /* optional */ }

        // 3. Firewall rules — check for open rules
        try {
          const rules: any[] = [];
          for await (const rule of mysqlClient.firewallRules.listByServer(rg, name)) rules.push(rule);

          const openRule = rules.find(r =>
            r.startIpAddress === '0.0.0.0' && r.endIpAddress === '255.255.255.255',
          );
          if (openRule) {
            findings.push(this.finding(
              'MySQL Flexible Server firewall allows access from all IP addresses',
              `MySQL Flexible Server "${name}" has a firewall rule allowing 0.0.0.0–255.255.255.255. Any internet-reachable host can attempt to connect to the database.`,
              'CRITICAL',
              { server: name, resourceGroup: rg, rule: openRule.name },
              'Remove the open-range firewall rule immediately. Use specific IP ranges for application servers or switch to private VNet access.',
              ['mysql', 'firewall', 'network'],
            ));
          } else if (rules.some(r => r.startIpAddress === '0.0.0.0')) {
            findings.push(this.finding(
              'MySQL Flexible Server has an overly permissive firewall rule',
              `MySQL Flexible Server "${name}" has a firewall rule starting from 0.0.0.0, allowing a broad range of internet hosts to connect.`,
              'HIGH',
              { server: name, resourceGroup: rg },
              'Replace broad IP rules with specific application server IPs or use VNet integration.',
              ['mysql', 'firewall'],
            ));
          }
        } catch { /* optional */ }

        // 4. Backup retention period
        const backupRetention = server.backup?.backupRetentionDays ?? 7;
        if (backupRetention < 7) {
          findings.push(this.finding(
            'MySQL Flexible Server has insufficient backup retention period',
            `MySQL Flexible Server "${name}" retains backups for only ${backupRetention} day(s). This limits recovery options in the event of data corruption or accidental deletion.`,
            'MEDIUM',
            { server: name, resourceGroup: rg, backupRetentionDays: backupRetention },
            'Set backup.backupRetentionDays to at least 7 days (35 days recommended for production workloads).',
            ['mysql', 'backup'],
          ));
        }

        // 5. Geo-redundant backup disabled
        const geoBackup = server.backup?.geoRedundantBackup ?? 'Disabled';
        if (geoBackup === 'Disabled') {
          findings.push(this.finding(
            'MySQL Flexible Server has geo-redundant backup disabled',
            `MySQL Flexible Server "${name}" does not geo-replicate backups. A full regional failure would leave the server unrecoverable from backup in another region.`,
            'MEDIUM',
            { server: name, resourceGroup: rg },
            'Enable geo-redundant backup to support cross-region restore in disaster scenarios.',
            ['mysql', 'backup', 'disaster-recovery'],
          ));
        }

        // 6. High Availability
        const haMode = server.highAvailability?.mode ?? 'Disabled';
        if (haMode === 'Disabled') {
          findings.push(this.finding(
            'MySQL Flexible Server has High Availability disabled',
            `MySQL Flexible Server "${name}" has no High Availability configured. Server failure requires manual recovery and results in extended downtime.`,
            'MEDIUM',
            { server: name, resourceGroup: rg },
            'Enable High Availability (ZoneRedundant or SameZone) for automatic failover and minimal downtime during failure events.',
            ['mysql', 'availability'],
          ));
        }

        // 7. Microsoft Entra ID administrator check intentionally omitted —
        // @azure/arm-mysql-flexible v3.1.0 does not expose azureADAdministrators operations.
        // Re-enable after upgrading the SDK.

        // 8. audit_log_enabled
        try {
          const auditLog = await mysqlClient.configurations.get(rg, name, 'audit_log_enabled');
          if (auditLog.value !== 'ON') {
            findings.push(this.finding(
              'MySQL Flexible Server audit logging is not enabled',
              `MySQL Flexible Server "${name}" has audit_log_enabled set to "${auditLog.value}". Without audit logs, privileged operations, schema changes, and failed authentication cannot be tracked.`,
              'MEDIUM',
              { server: name, resourceGroup: rg, auditLogEnabled: auditLog.value },
              'Set audit_log_enabled to "ON" and configure audit_log_events to capture CONNECTION, GENERAL, and TABLE_ACCESS events.',
              ['mysql', 'logging', 'audit'],
            ));
          }
        } catch { /* optional */ }

        // 9. MySQL version EOL
        if (version === '5.7' || version === '5.6') {
          findings.push(this.finding(
            'MySQL Flexible Server runs an end-of-life MySQL version',
            `MySQL Flexible Server "${name}" runs MySQL ${version}. MySQL 5.7 reaches end-of-life in October 2025 and MySQL 5.6 is already EOL. No further security patches will be provided.`,
            'HIGH',
            { server: name, resourceGroup: rg, version },
            'Upgrade to MySQL 8.0 or later. Test application compatibility and connection string changes (e.g., authentication_plugin changes) in a non-production environment first.',
            ['mysql', 'eol-version'],
          ));
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure MySQL scan error',
        `Could not complete MySQL Flexible Server scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on MySQL Flexible Server resources.',
      ));
    }

    return findings;
  }
}
