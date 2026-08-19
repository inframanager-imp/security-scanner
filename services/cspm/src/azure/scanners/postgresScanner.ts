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
          findings.push(this.emit(
            'azure_postgresql_public_network_access_disabled',
            { server: name, resourceGroup: rg, version },
            { message: `PostgreSQL Flexible Server "${name}" is accessible from the public internet. Combined with weak firewall rules, this exposes the database to brute-force and SQL injection attacks.` },
          ));
        }

        // 2. SSL enforcement
        try {
          const sslConfig = await pgClient.configurations.get(rg, name, 'require_secure_transport');
          if (sslConfig.value !== 'on') {
            findings.push(this.emit(
              'azure_postgresql_ssl_enforced',
              { server: name, resourceGroup: rg, requireSecureTransport: sslConfig.value },
              { message: `PostgreSQL Flexible Server "${name}" has require_secure_transport set to "${sslConfig.value}". Unencrypted connections transmit credentials and data in plaintext.` },
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
            findings.push(this.emit(
              'azure_postgresql_firewall_no_open_range',
              { server: name, resourceGroup: rg, rule: openRule.name },
              { message: `PostgreSQL Flexible Server "${name}" has a firewall rule allowing 0.0.0.0–255.255.255.255. Any internet host can attempt to connect to the database.` },
            ));
          } else if (rules.some(r => r.startIpAddress === '0.0.0.0')) {
            findings.push(this.emit(
              'azure_postgresql_firewall_no_open_range',
              { server: name, resourceGroup: rg },
              { message: `PostgreSQL Flexible Server "${name}" has a firewall rule starting from 0.0.0.0. This allows connections from a broad range of internet hosts.` },
            ));
          }
        } catch { /* firewall rules optional */ }

        // 4. Backup retention period
        const backupRetention = server.backup?.backupRetentionDays ?? 7;
        if (backupRetention < 7) {
          findings.push(this.emit(
            'azure_postgresql_backup_retention_sufficient',
            { server: name, resourceGroup: rg, backupRetentionDays: backupRetention },
            { message: `PostgreSQL Flexible Server "${name}" retains backups for only ${backupRetention} day(s). Short retention limits recovery options after data corruption or accidental deletion.` },
          ));
        }

        // 5. Geo-redundant backup disabled
        const geoBackup = server.backup?.geoRedundantBackup ?? 'Disabled';
        if (geoBackup === 'Disabled') {
          findings.push(this.emit(
            'azure_postgresql_geo_redundant_backup_enabled',
            { server: name, resourceGroup: rg },
            { message: `PostgreSQL Flexible Server "${name}" does not use geo-redundant backups. A regional disaster would leave the server unrecoverable from backup in another region.` },
          ));
        }

        // 6. High Availability not configured
        const haMode = server.highAvailability?.mode ?? 'Disabled';
        if (haMode === 'Disabled') {
          findings.push(this.emit(
            'azure_postgresql_high_availability_enabled',
            { server: name, resourceGroup: rg },
            { message: `PostgreSQL Flexible Server "${name}" has no High Availability configuration. A server failure requires manual intervention and results in extended downtime.` },
          ));
        }

        // 7. Microsoft Entra ID authentication
        const authConfig = server.authConfig;
        const entraEnabled = authConfig?.activeDirectoryAuth === 'Enabled';
        if (!entraEnabled) {
          findings.push(this.emit(
            'postgresql_flexible_server_entra_id_authentication_enabled',
            { server: name, resourceGroup: rg },
            { message: `PostgreSQL Flexible Server "${name}" relies solely on password-based authentication. Passwords cannot be centrally managed, rotated automatically, or scoped by application identity.` },
          ));
        }

        // 8. PostgreSQL version EOL check
        if (version === '11') {
          findings.push(this.emit(
            'azure_postgresql_version_not_eol',
            { server: name, resourceGroup: rg, version },
            { message: `PostgreSQL Flexible Server "${name}" runs PostgreSQL ${version}. PostgreSQL 11 reached EOL in November 2023 and no longer receives security patches from the community.` },
          ));
        }

        // 9. Connection throttling / log_connections
        try {
          const logConn = await pgClient.configurations.get(rg, name, 'log_connections');
          if (logConn.value !== 'on') {
            findings.push(this.emit(
              'postgresql_flexible_server_log_connections_on',
              { server: name, resourceGroup: rg, logConnections: logConn.value },
              { message: `PostgreSQL Flexible Server "${name}" has log_connections set to "${logConn.value}". Without connection logging, unauthorized access attempts cannot be detected from logs.` },
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
