import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class GcpSQLScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-CloudSQL');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      const sqladmin = this.client.sqladmin();
      const res      = await sqladmin.instances.list({ project });
      const instances = res.data.items ?? [];

      if (instances.length === 0) return findings;

      for (const inst of instances) {
        const name     = inst.name ?? 'unknown';
        const dbVer    = inst.databaseVersion ?? 'unknown';
        const settings = inst.settings ?? {};
        const ipConfig = settings.ipConfiguration ?? {};

        // 1. Public IP enabled
        const publicIp = ipConfig.ipv4Enabled === true;
        if (publicIp) {
          findings.push(this.finding(
            'Cloud SQL instance has a public IP address',
            `Cloud SQL instance "${name}" (${dbVer}) has a public IPv4 address. Even with authorized networks configured, exposing a database to the public internet increases attack surface.`,
            'HIGH',
            { instance: name, dbVersion: dbVer, project },
            'Disable the public IP on the Cloud SQL instance and connect via Cloud SQL Auth Proxy or Private Service Connect using a private IP.',
            ['cloudsql', 'network', 'public-ip'],
          ));
        }

        // 2. Authorized networks — check for 0.0.0.0/0
        const authorizedNetworks = ipConfig.authorizedNetworks ?? [];
        const openNet = authorizedNetworks.find((n: any) => n.value === '0.0.0.0/0');
        if (openNet) {
          findings.push(this.finding(
            'Cloud SQL instance allows connections from all IP addresses',
            `Cloud SQL instance "${name}" has an authorized network rule allowing 0.0.0.0/0. Any internet host can attempt to connect to the database.`,
            'CRITICAL',
            { instance: name, project, authorizedNetwork: '0.0.0.0/0' },
            'Remove the 0.0.0.0/0 authorized network. Restrict to specific application server IPs or use Cloud SQL Auth Proxy / Private IP exclusively.',
            ['cloudsql', 'firewall', 'network'],
          ));
        }

        // 3. SSL/TLS enforcement
        const requireSsl = ipConfig.requireSsl === true || ipConfig.sslMode === 'ENCRYPTED_ONLY' || ipConfig.sslMode === 'TRUSTED_CLIENT_CERTIFICATE_REQUIRED';
        if (!requireSsl) {
          findings.push(this.finding(
            'Cloud SQL instance does not require SSL connections',
            `Cloud SQL instance "${name}" does not enforce SSL/TLS for client connections. Database credentials and query data can be transmitted in plaintext.`,
            'CRITICAL',
            { instance: name, dbVersion: dbVer, project, requireSsl: ipConfig.requireSsl, sslMode: ipConfig.sslMode },
            'Enable SSL enforcement on the Cloud SQL instance. Set requireSsl=true or sslMode=ENCRYPTED_ONLY. Update all client connection strings to use SSL certificates.',
            ['cloudsql', 'encryption-in-transit', 'ssl'],
          ));
        }

        // 4. Automated backups disabled
        const backupConfig = settings.backupConfiguration ?? {};
        if (!backupConfig.enabled) {
          findings.push(this.finding(
            'Cloud SQL instance has automated backups disabled',
            `Cloud SQL instance "${name}" does not have automated backups enabled. Without backups, data loss from accidental deletion, corruption, or ransomware cannot be recovered.`,
            'HIGH',
            { instance: name, dbVersion: dbVer, project },
            'Enable automated backups on the Cloud SQL instance. Configure a backup window during off-peak hours and set a retention period of at least 7 days.',
            ['cloudsql', 'backup'],
          ));
        }

        // 5. Point-in-time recovery disabled
        if (!backupConfig.pointInTimeRecoveryEnabled && backupConfig.enabled) {
          findings.push(this.finding(
            'Cloud SQL instance has Point-in-Time Recovery (PITR) disabled',
            `Cloud SQL instance "${name}" has PITR disabled. Without PITR, you can only restore to automated backup snapshots (daily), not to arbitrary points in time.`,
            'MEDIUM',
            { instance: name, dbVersion: dbVer, project },
            'Enable Point-in-Time Recovery on the Cloud SQL instance to allow restoration to any point within the retention window.',
            ['cloudsql', 'backup', 'pitr'],
          ));
        }

        // 6. High availability disabled
        const haEnabled = inst.instanceType === 'CLOUD_SQL_INSTANCE' &&
          settings.availabilityType === 'REGIONAL';
        if (!haEnabled) {
          findings.push(this.finding(
            'Cloud SQL instance has High Availability (HA) disabled',
            `Cloud SQL instance "${name}" uses zonal deployment (availabilityType: "${settings.availabilityType ?? 'ZONAL'}"). A zone failure results in database unavailability until automatic or manual recovery.`,
            'MEDIUM',
            { instance: name, project, availabilityType: settings.availabilityType },
            'Set availabilityType to REGIONAL for production Cloud SQL instances to enable automatic failover to a standby instance in another zone.',
            ['cloudsql', 'availability'],
          ));
        }

        // 7. Database flags — security-relevant settings
        const flags = settings.databaseFlags ?? [];
        const flagMap = Object.fromEntries(flags.map((f: any) => [f.name, f.value]));

        // PostgreSQL: log_connections, log_disconnections, log_min_messages
        if (dbVer.startsWith('POSTGRES')) {
          if (flagMap['log_connections'] !== 'on') {
            findings.push(this.finding(
              'Cloud SQL PostgreSQL instance does not log connections',
              `Cloud SQL instance "${name}" has log_connections disabled. Connection attempts, including failed authentication, are not logged.`,
              'MEDIUM',
              { instance: name, project, flag: 'log_connections', value: flagMap['log_connections'] ?? 'off' },
              'Set the log_connections database flag to "on" to record all new client connections.',
              ['cloudsql', 'logging', 'postgresql'],
            ));
          }
          if (flagMap['log_disconnections'] !== 'on') {
            findings.push(this.finding(
              'Cloud SQL PostgreSQL instance does not log disconnections',
              `Cloud SQL instance "${name}" has log_disconnections disabled. Session duration and disconnect events are not captured.`,
              'LOW',
              { instance: name, project, flag: 'log_disconnections' },
              'Set the log_disconnections database flag to "on".',
              ['cloudsql', 'logging', 'postgresql'],
            ));
          }
        }

        // MySQL: general_log, audit flags
        if (dbVer.startsWith('MYSQL')) {
          if (flagMap['local_infile'] === 'on' || flagMap['local_infile'] === '1') {
            findings.push(this.finding(
              'Cloud SQL MySQL instance has local_infile enabled',
              `Cloud SQL instance "${name}" has the local_infile flag enabled. This allows clients to load data from local files, which can be exploited to read sensitive files from the database server or client.`,
              'HIGH',
              { instance: name, project, flag: 'local_infile' },
              'Set the local_infile database flag to "off" on the Cloud SQL MySQL instance.',
              ['cloudsql', 'mysql', 'security-flag'],
            ));
          }
          if (flagMap['skip_show_database'] !== 'on') {
            findings.push(this.finding(
              'Cloud SQL MySQL instance has skip_show_database disabled',
              `Cloud SQL instance "${name}" allows any user to run SHOW DATABASES without the SHOW DATABASES privilege. This can reveal database names to unprivileged users.`,
              'LOW',
              { instance: name, project, flag: 'skip_show_database' },
              'Set the skip_show_database database flag to "on".',
              ['cloudsql', 'mysql', 'security-flag'],
            ));
          }
        }

        // SQL Server: cross-db ownership chaining, contained database auth
        if (dbVer.startsWith('SQLSERVER')) {
          if (flagMap['cross db ownership chaining'] === 'on') {
            findings.push(this.finding(
              'Cloud SQL SQL Server has cross-database ownership chaining enabled',
              `Cloud SQL instance "${name}" has cross-database ownership chaining enabled, which can allow privilege escalation between databases.`,
              'HIGH',
              { instance: name, project, flag: 'cross db ownership chaining' },
              'Set the "cross db ownership chaining" flag to "off".',
              ['cloudsql', 'sqlserver', 'security-flag'],
            ));
          }
          if (flagMap['contained database authentication'] === 'on') {
            findings.push(this.finding(
              'Cloud SQL SQL Server has contained database authentication enabled',
              `Cloud SQL instance "${name}" has contained database authentication enabled. Contained databases authenticate users at the database level, bypassing server-level logins and making password policy enforcement harder.`,
              'MEDIUM',
              { instance: name, project, flag: 'contained database authentication' },
              'Set the "contained database authentication" flag to "off" unless contained databases are specifically required.',
              ['cloudsql', 'sqlserver', 'security-flag'],
            ));
          }
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'GCP Cloud SQL scan error',
        `Could not complete Cloud SQL scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service account has roles/cloudsql.viewer on the project.',
      ));
    }

    return findings;
  }
}
