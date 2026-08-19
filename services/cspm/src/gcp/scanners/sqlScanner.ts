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
          findings.push(this.emit(
            'cloudsql_instance_public_ip',
            { instance: name, dbVersion: dbVer, project },
            { message: `Cloud SQL instance "${name}" (${dbVer}) has a public IPv4 address. Even with authorized networks configured, exposing a database to the public internet increases attack surface.` },
          ));
        }

        // 2. Authorized networks — check for 0.0.0.0/0
        const authorizedNetworks = ipConfig.authorizedNetworks ?? [];
        const openNet = authorizedNetworks.find((n: any) => n.value === '0.0.0.0/0');
        if (openNet) {
          findings.push(this.emit(
            'cloudsql_instance_public_access',
            { instance: name, project, authorizedNetwork: '0.0.0.0/0' },
            { message: `Cloud SQL instance "${name}" has an authorized network rule allowing 0.0.0.0/0. Any internet host can attempt to connect to the database.` },
          ));
        }

        // 3. SSL/TLS enforcement
        const requireSsl = ipConfig.requireSsl === true || ipConfig.sslMode === 'ENCRYPTED_ONLY' || ipConfig.sslMode === 'TRUSTED_CLIENT_CERTIFICATE_REQUIRED';
        if (!requireSsl) {
          findings.push(this.emit(
            'cloudsql_instance_ssl_connections',
            { instance: name, dbVersion: dbVer, project, requireSsl: ipConfig.requireSsl, sslMode: ipConfig.sslMode },
            { message: `Cloud SQL instance "${name}" does not enforce SSL/TLS for client connections. Database credentials and query data can be transmitted in plaintext.` },
          ));
        }

        // 4. Automated backups disabled
        const backupConfig = settings.backupConfiguration ?? {};
        if (!backupConfig.enabled) {
          findings.push(this.emit(
            'cloudsql_instance_automated_backups',
            { instance: name, dbVersion: dbVer, project },
            { message: `Cloud SQL instance "${name}" does not have automated backups enabled. Without backups, data loss from accidental deletion, corruption, or ransomware cannot be recovered.` },
          ));
        }

        // 5. Point-in-time recovery disabled
        if (!backupConfig.pointInTimeRecoveryEnabled && backupConfig.enabled) {
          findings.push(this.emit(
            'cloudsql_instance_point_in_time_recovery_enabled',
            { instance: name, dbVersion: dbVer, project },
            { message: `Cloud SQL instance "${name}" has PITR disabled. Without PITR, you can only restore to automated backup snapshots (daily), not to arbitrary points in time.` },
          ));
        }

        // 6. High availability disabled
        const haEnabled = inst.instanceType === 'CLOUD_SQL_INSTANCE' &&
          settings.availabilityType === 'REGIONAL';
        if (!haEnabled) {
          findings.push(this.emit(
            'cloudsql_instance_high_availability_enabled',
            { instance: name, project, availabilityType: settings.availabilityType },
            { message: `Cloud SQL instance "${name}" uses zonal deployment (availabilityType: "${settings.availabilityType ?? 'ZONAL'}"). A zone failure results in database unavailability until automatic or manual recovery.` },
          ));
        }

        // 7. Database flags — security-relevant settings
        const flags = settings.databaseFlags ?? [];
        const flagMap = Object.fromEntries(flags.map((f: any) => [f.name, f.value]));

        // PostgreSQL: log_connections, log_disconnections, log_min_messages
        if (dbVer.startsWith('POSTGRES')) {
          if (flagMap['log_connections'] !== 'on') {
            findings.push(this.emit(
              'cloudsql_instance_postgres_log_connections_flag',
              { instance: name, project, flag: 'log_connections', value: flagMap['log_connections'] ?? 'off' },
              { message: `Cloud SQL instance "${name}" has log_connections disabled. Connection attempts, including failed authentication, are not logged.` },
            ));
          }
          if (flagMap['log_disconnections'] !== 'on') {
            findings.push(this.emit(
              'cloudsql_instance_postgres_log_disconnections_flag',
              { instance: name, project, flag: 'log_disconnections' },
              { message: `Cloud SQL instance "${name}" has log_disconnections disabled. Session duration and disconnect events are not captured.` },
            ));
          }
        }

        // MySQL: general_log, audit flags
        if (dbVer.startsWith('MYSQL')) {
          if (flagMap['local_infile'] === 'on' || flagMap['local_infile'] === '1') {
            findings.push(this.emit(
              'cloudsql_instance_mysql_local_infile_flag',
              { instance: name, project, flag: 'local_infile' },
              { message: `Cloud SQL instance "${name}" has the local_infile flag enabled. This allows clients to load data from local files, which can be exploited to read sensitive files from the database server or client.` },
            ));
          }
          if (flagMap['skip_show_database'] !== 'on') {
            findings.push(this.emit(
              'cloudsql_instance_mysql_skip_show_database_flag',
              { instance: name, project, flag: 'skip_show_database' },
              { message: `Cloud SQL instance "${name}" allows any user to run SHOW DATABASES without the SHOW DATABASES privilege. This can reveal database names to unprivileged users.` },
            ));
          }
        }

        // SQL Server: cross-db ownership chaining, contained database auth
        if (dbVer.startsWith('SQLSERVER')) {
          if (flagMap['cross db ownership chaining'] === 'on') {
            findings.push(this.emit(
              'cloudsql_instance_sqlserver_cross_db_ownership_chaining_flag',
              { instance: name, project, flag: 'cross db ownership chaining' },
              { message: `Cloud SQL instance "${name}" has cross-database ownership chaining enabled, which can allow privilege escalation between databases.` },
            ));
          }
          if (flagMap['contained database authentication'] === 'on') {
            findings.push(this.emit(
              'cloudsql_instance_sqlserver_contained_database_authentication_flag',
              { instance: name, project, flag: 'contained database authentication' },
              { message: `Cloud SQL instance "${name}" has contained database authentication enabled. Contained databases authenticate users at the database level, bypassing server-level logins and making password policy enforcement harder.` },
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
