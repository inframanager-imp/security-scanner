// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

async function getConfig(pgClient: any, rg: string, name: string, param: string): Promise<string | undefined> {
  try {
    const cfg = await pgClient.configurations.get(rg, name, param);
    return cfg?.value;
  } catch {
    return undefined;
  }
}

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
            {
              message: `PostgreSQL Flexible Server "${name}" is accessible from the public internet. Combined with weak firewall rules, this exposes the database to brute-force and SQL injection attacks.`,
            },
          ));
        }

        // 2. SSL enforcement
        const sslValue = await getConfig(pgClient, rg, name, 'require_secure_transport');
        if (sslValue !== undefined && sslValue !== 'on') {
          findings.push(this.emit(
            'azure_postgresql_ssl_enforced',
            { server: name, resourceGroup: rg, requireSecureTransport: sslValue },
            {
              message: `PostgreSQL Flexible Server "${name}" has require_secure_transport set to "${sslValue}". Unencrypted connections transmit credentials and data in plaintext.`,
            },
          ));
        }

        // 3. Firewall rules — check for all-IP rules and the "allow Azure services" rule
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
              {
                message: `PostgreSQL Flexible Server "${name}" has a firewall rule allowing 0.0.0.0–255.255.255.255. Any internet host can attempt to connect to the database.`,
              },
            ));
          } else if (rules.some(r => r.startIpAddress === '0.0.0.0')) {
            findings.push(this.emit(
              'azure_postgresql_firewall_no_open_range',
              { server: name, resourceGroup: rg },
              {
                message: `PostgreSQL Flexible Server "${name}" has a firewall rule starting from 0.0.0.0. This allows connections from a broad range of internet hosts.`,
              },
            ));
          }

          // postgresql_flexible_server_allow_access_services_disabled — the
          // special "Allow public access from any Azure service" rule is a
          // firewall entry with start/end IP both 0.0.0.0.
          const allowAzureServicesRule = rules.find(r =>
            r.startIpAddress === '0.0.0.0' && r.endIpAddress === '0.0.0.0',
          );
          if (allowAzureServicesRule) {
            findings.push(this.emit(
              'postgresql_flexible_server_allow_access_services_disabled',
              { server: name, resourceGroup: rg, rule: allowAzureServicesRule.name },
              {
                message: `PostgreSQL Flexible Server "${name}" has "Allow public access from any Azure service within Azure" enabled, permitting any Azure tenant's resources to reach the server.`,
              },
            ));
          }
        } catch { /* firewall rules optional */ }

        // 4. Backup retention period
        const backupRetention = server.backup?.backupRetentionDays ?? 7;
        if (backupRetention < 7) {
          findings.push(this.emit(
            'azure_postgresql_backup_retention_sufficient',
            { server: name, resourceGroup: rg, backupRetentionDays: backupRetention },
            {
              message: `PostgreSQL Flexible Server "${name}" retains backups for only ${backupRetention} day(s). Short retention limits recovery options after data corruption or accidental deletion.`,
            },
          ));
        }

        // 5. Geo-redundant backup disabled
        const geoBackup = server.backup?.geoRedundantBackup ?? 'Disabled';
        if (geoBackup === 'Disabled') {
          findings.push(this.emit(
            'azure_postgresql_geo_redundant_backup_enabled',
            { server: name, resourceGroup: rg },
            {
              message: `PostgreSQL Flexible Server "${name}" does not use geo-redundant backups. A regional disaster would leave the server unrecoverable from backup in another region.`,
            },
          ));
        }

        // 6. High Availability not configured
        const haMode = server.highAvailability?.mode ?? 'Disabled';
        if (haMode === 'Disabled') {
          findings.push(this.emit(
            'azure_postgresql_high_availability_enabled',
            { server: name, resourceGroup: rg },
            {
              message: `PostgreSQL Flexible Server "${name}" has no High Availability configuration. A server failure requires manual intervention and results in extended downtime.`,
            },
          ));
        }

        // 7. Microsoft Entra ID authentication
        const authConfig = server.authConfig;
        const entraEnabled = authConfig?.activeDirectoryAuth === 'Enabled';
        if (!entraEnabled) {
          findings.push(this.emit(
            'postgresql_flexible_server_entra_id_authentication_enabled',
            { server: name, resourceGroup: rg },
            {
              message: `PostgreSQL Flexible Server "${name}" relies solely on password-based authentication. Passwords cannot be centrally managed, rotated automatically, or scoped by application identity.`,
            },
          ));
        }

        // 8. PostgreSQL version EOL check
        if (version === '11') {
          findings.push(this.emit(
            'azure_postgresql_version_not_eol',
            { server: name, resourceGroup: rg, version },
            {
              message: `PostgreSQL Flexible Server "${name}" runs PostgreSQL ${version}. PostgreSQL 11 reached EOL in November 2023 and no longer receives security patches from the community.`,
            },
          ));
        }

        // 9. Connection throttling / logging server parameters
        const logConn = await getConfig(pgClient, rg, name, 'log_connections');
        if (logConn !== undefined && logConn !== 'on') {
          findings.push(this.emit(
            'postgresql_flexible_server_log_connections_on',
            { server: name, resourceGroup: rg, logConnections: logConn },
            {
              message: `PostgreSQL Flexible Server "${name}" has log_connections set to "${logConn}". Without connection logging, unauthorized access attempts cannot be detected from logs.`,
            },
          ));
        }

        const connThrottling = await getConfig(pgClient, rg, name, 'connection_throttling');
        if (connThrottling !== undefined && connThrottling !== 'on') {
          findings.push(this.emit(
            'postgresql_flexible_server_connection_throttling_on',
            { server: name, resourceGroup: rg, connectionThrottling: connThrottling },
            {
              message: `PostgreSQL Flexible Server "${name}" has connection_throttling set to "${connThrottling}". Without throttling, the server is more vulnerable to brute-force login attempts.`,
            },
          ));
        }

        const logCheckpoints = await getConfig(pgClient, rg, name, 'log_checkpoints');
        if (logCheckpoints !== undefined && logCheckpoints !== 'on') {
          findings.push(this.emit(
            'postgresql_flexible_server_log_checkpoints_on',
            { server: name, resourceGroup: rg, logCheckpoints },
            {
              message: `PostgreSQL Flexible Server "${name}" has log_checkpoints set to "${logCheckpoints}". Checkpoint activity is not recorded for performance and integrity troubleshooting.`,
            },
          ));
        }

        const logDisconnections = await getConfig(pgClient, rg, name, 'log_disconnections');
        if (logDisconnections !== undefined && logDisconnections !== 'on') {
          findings.push(this.emit(
            'postgresql_flexible_server_log_disconnections_on',
            { server: name, resourceGroup: rg, logDisconnections },
            {
              message: `PostgreSQL Flexible Server "${name}" has log_disconnections set to "${logDisconnections}". Session end events are not recorded, leaving an incomplete audit trail.`,
            },
          ));
        }

        const logRetentionDays = await getConfig(pgClient, rg, name, 'log_retention_days');
        if (logRetentionDays !== undefined) {
          const days = Number(logRetentionDays);
          if (isNaN(days) || days <= 3 || days >= 8) {
            findings.push(this.emit(
              'postgresql_flexible_server_log_retention_days_greater_3',
              { server: name, resourceGroup: rg, logRetentionDays },
              {
                message: `PostgreSQL Flexible Server "${name}" has log_retention_days set to "${logRetentionDays}", outside the recommended 4-7 day range.`,
              },
            ));
          }
        }
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
