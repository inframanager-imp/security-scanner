import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzurePostgresScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-PostgreSQL');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const pgClient = this.client.postgres();

      const servers: any[] = [];
      for await (const srv of pgClient.servers.listBySubscription()) servers.push(srv);

      if (servers.length === 0) return findings;

      for (const server of servers) {
        const name = server.name ?? 'unknown';
        const rg   = server.id?.split('/')[4] ?? 'unknown';
        const version = server.version ?? 'unknown';

        // 1. Public network access enabled
        const publicAccess = server.network?.publicNetworkAccess ?? 'Enabled';
        if (publicAccess === 'Enabled') {
          findings.push(this.finding(
            'PostgreSQL Flexible Server has public network access enabled',
            `PostgreSQL Flexible Server "${name}" is accessible from the public internet. Combined with weak firewall rules, this exposes the database to brute-force and SQL injection attacks.`,
            'HIGH',
            { server: name, resourceGroup: rg, version },
            'Set network.publicNetworkAccess to "Disabled" and configure private access (VNet integration) to restrict connectivity to trusted networks.',
            ['postgresql', 'network', 'public-access'],
          ));
        }

        // 2. SSL enforcement
        try {
          const sslConfig = await pgClient.configurations.get(rg, name, 'require_secure_transport');
          if (sslConfig.value !== 'on') {
            findings.push(this.finding(
              'PostgreSQL Flexible Server does not require SSL connections',
              `PostgreSQL Flexible Server "${name}" has require_secure_transport set to "${sslConfig.value}". Unencrypted connections transmit credentials and data in plaintext.`,
              'CRITICAL',
              { server: name, resourceGroup: rg, requireSecureTransport: sslConfig.value },
              'Set the require_secure_transport server parameter to "on". Update all application connection strings to use SSL mode "require" or higher.',
              ['postgresql', 'encryption-in-transit', 'ssl'],
            ));
          }
        } catch { /* configuration check optional */ }

        // 3. Firewall rules — check for all-IP rules
        try {
          const rules: any[] = [];
          for await (const rule of pgClient.firewallRules.listByServer(rg, name)) rules.push(rule);

          const openRule = rules.find(r =>
            r.startIpAddress === '0.0.0.0' && r.endIpAddress === '255.255.255.255',
          );
          if (openRule) {
            findings.push(this.finding(
              'PostgreSQL Flexible Server firewall allows access from all IP addresses',
              `PostgreSQL Flexible Server "${name}" has a firewall rule allowing 0.0.0.0–255.255.255.255. Any internet host can attempt to connect to the database.`,
              'CRITICAL',
              { server: name, resourceGroup: rg, rule: openRule.name },
              'Remove the open-range firewall rule. Restrict access to specific application server IPs or use private access (VNet integration) instead.',
              ['postgresql', 'firewall', 'network'],
            ));
          } else if (rules.some(r => r.startIpAddress === '0.0.0.0')) {
            findings.push(this.finding(
              'PostgreSQL Flexible Server has an overly permissive firewall rule',
              `PostgreSQL Flexible Server "${name}" has a firewall rule starting from 0.0.0.0. This allows connections from a broad range of internet hosts.`,
              'HIGH',
              { server: name, resourceGroup: rg },
              'Replace broad firewall rules with specific application server IP ranges or switch to private VNet access.',
              ['postgresql', 'firewall'],
            ));
          }
        } catch { /* firewall rules optional */ }

        // 4. Backup retention period
        const backupRetention = server.backup?.backupRetentionDays ?? 7;
        if (backupRetention < 7) {
          findings.push(this.finding(
            'PostgreSQL Flexible Server has insufficient backup retention period',
            `PostgreSQL Flexible Server "${name}" retains backups for only ${backupRetention} day(s). Short retention limits recovery options after data corruption or accidental deletion.`,
            'MEDIUM',
            { server: name, resourceGroup: rg, backupRetentionDays: backupRetention },
            'Set backup.backupRetentionDays to at least 7 days (35 days recommended for production) to ensure adequate recovery point objectives.',
            ['postgresql', 'backup'],
          ));
        }

        // 5. Geo-redundant backup disabled
        const geoBackup = server.backup?.geoRedundantBackup ?? 'Disabled';
        if (geoBackup === 'Disabled') {
          findings.push(this.finding(
            'PostgreSQL Flexible Server has geo-redundant backup disabled',
            `PostgreSQL Flexible Server "${name}" does not use geo-redundant backups. A regional disaster would leave the server unrecoverable from backup in another region.`,
            'MEDIUM',
            { server: name, resourceGroup: rg },
            'Enable geo-redundant backup to allow restore to a paired Azure region in case of a full regional failure.',
            ['postgresql', 'backup', 'disaster-recovery'],
          ));
        }

        // 6. High Availability not configured
        const haMode = server.highAvailability?.mode ?? 'Disabled';
        if (haMode === 'Disabled') {
          findings.push(this.finding(
            'PostgreSQL Flexible Server has High Availability disabled',
            `PostgreSQL Flexible Server "${name}" has no High Availability configuration. A server failure requires manual intervention and results in extended downtime.`,
            'MEDIUM',
            { server: name, resourceGroup: rg },
            'Enable High Availability (ZoneRedundant or SameZone mode) to allow automatic failover with minimal downtime.',
            ['postgresql', 'availability'],
          ));
        }

        // 7. Microsoft Entra ID authentication
        const authConfig = server.authConfig;
        const entraEnabled = authConfig?.activeDirectoryAuth === 'Enabled';
        if (!entraEnabled) {
          findings.push(this.finding(
            'PostgreSQL Flexible Server does not use Microsoft Entra ID authentication',
            `PostgreSQL Flexible Server "${name}" relies solely on password-based authentication. Passwords cannot be centrally managed, rotated automatically, or scoped by application identity.`,
            'MEDIUM',
            { server: name, resourceGroup: rg },
            'Enable Microsoft Entra ID authentication (authConfig.activeDirectoryAuth = "Enabled") and migrate applications to use Managed Identity or service principal tokens.',
            ['postgresql', 'authentication', 'entra-id'],
          ));
        }

        // 8. PostgreSQL version EOL check
        if (version === '11') {
          findings.push(this.finding(
            'PostgreSQL Flexible Server runs an end-of-life PostgreSQL version',
            `PostgreSQL Flexible Server "${name}" runs PostgreSQL ${version}. PostgreSQL 11 reached EOL in November 2023 and no longer receives security patches from the community.`,
            'HIGH',
            { server: name, resourceGroup: rg, version },
            'Upgrade to PostgreSQL 15 or 16. Test application compatibility in a non-production environment using the major version upgrade feature of Flexible Server.',
            ['postgresql', 'eol-version'],
          ));
        }

        // 9. Connection throttling / log_connections
        try {
          const logConn = await pgClient.configurations.get(rg, name, 'log_connections');
          if (logConn.value !== 'on') {
            findings.push(this.finding(
              'PostgreSQL Flexible Server does not log database connections',
              `PostgreSQL Flexible Server "${name}" has log_connections set to "${logConn.value}". Without connection logging, unauthorized access attempts cannot be detected from logs.`,
              'LOW',
              { server: name, resourceGroup: rg, logConnections: logConn.value },
              'Set the log_connections server parameter to "on" to record all new client connections to the server.',
              ['postgresql', 'logging'],
            ));
          }
        } catch { /* optional */ }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure PostgreSQL scan error',
        `Could not complete PostgreSQL Flexible Server scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on PostgreSQL Flexible Server resources.',
      ));
    }

    return findings;
  }
}
