// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
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
        const ipAddresses = inst.ipAddresses ?? [];

        // cloudsql_instance_public_ip: instance has a PRIMARY (public) IP address
        const publicIp = ipAddresses.some((a: any) => a.type === 'PRIMARY');
        if (publicIp) {
          findings.push(this.emit(
            'cloudsql_instance_public_ip',
            { instance: name, dbVersion: dbVer, project, ipAddresses },
            { message: `Cloud SQL instance "${name}" (${dbVer}) has a public IPv4 address. Even with authorized networks configured, exposing a database to the public internet increases attack surface.` },
          ));
        }

        // cloudsql_instance_private_ip_assignment: every IP assigned must be PRIVATE
        const hasNonPrivateIp = ipAddresses.some((a: any) => a.type !== 'PRIVATE');
        if (ipAddresses.length > 0 && hasNonPrivateIp) {
          findings.push(this.emit(
            'cloudsql_instance_private_ip_assignment',
            { instance: name, dbVersion: dbVer, project, ipAddresses },
            { message: `Cloud SQL instance "${name}" has one or more non-private IP assignments and is not restricted to private connectivity only.` },
          ));
        }

        // cloudsql_instance_public_access — authorized networks contain 0.0.0.0/0
        const authorizedNetworks = ipConfig.authorizedNetworks ?? [];
        const openNet = authorizedNetworks.find((n: any) => n.value === '0.0.0.0/0');
        if (openNet) {
          findings.push(this.emit(
            'cloudsql_instance_public_access',
            { instance: name, project, authorizedNetwork: '0.0.0.0/0' },
            { message: `Cloud SQL instance "${name}" has an authorized network rule allowing 0.0.0.0/0. Any internet host can attempt to connect to the database.` },
          ));
        }

        // cloudsql_instance_ssl_connections
        const sslMode = ipConfig.sslMode ?? 'ALLOW_UNENCRYPTED_AND_ENCRYPTED';
        const requireSsl = ipConfig.requireSsl === true;
        const sslFail = sslMode === 'ALLOW_UNENCRYPTED_AND_ENCRYPTED' ||
          (sslMode === 'SSL_MODE_UNSPECIFIED' && !requireSsl);
        if (sslFail) {
          findings.push(this.emit(
            'cloudsql_instance_ssl_connections',
            { instance: name, dbVersion: dbVer, project, requireSsl, sslMode },
            { message: `Cloud SQL instance "${name}" does not enforce SSL/TLS for client connections. Database credentials and query data can be transmitted in plaintext.` },
          ));
        }

        // cloudsql_instance_automated_backups
        const backupConfig = settings.backupConfiguration ?? {};
        if (!backupConfig.enabled) {
          findings.push(this.emit(
            'cloudsql_instance_automated_backups',
            { instance: name, dbVersion: dbVer, project },
            { message: `Cloud SQL instance "${name}" does not have automated backups enabled. Without backups, data loss from accidental deletion, corruption, or ransomware cannot be recovered.` },
          ));
        }

        // cloudsql_instance_point_in_time_recovery_enabled (not a Prowler check; retained pre-existing coverage)
        if (backupConfig.enabled && !backupConfig.pointInTimeRecoveryEnabled) {
          findings.push(this.emit(
            'cloudsql_instance_point_in_time_recovery_enabled',
            { instance: name, dbVersion: dbVer, project },
            { message: `Cloud SQL instance "${name}" has PITR disabled. Without PITR, you can only restore to automated backup snapshots (daily), not to arbitrary points in time.` },
          ));
        }

        // cloudsql_instance_high_availability_enabled
        const haEnabled = inst.instanceType === 'CLOUD_SQL_INSTANCE' &&
          settings.availabilityType === 'REGIONAL';
        if (!haEnabled) {
          findings.push(this.emit(
            'cloudsql_instance_high_availability_enabled',
            { instance: name, project, availabilityType: settings.availabilityType },
            { message: `Cloud SQL instance "${name}" uses zonal deployment (availabilityType: "${settings.availabilityType ?? 'ZONAL'}"). A zone failure results in database unavailability until automatic or manual recovery.` },
          ));
        }

        // cloudsql_instance_cmek_encryption_enabled (skip replicas/other non-primary instance types, matching Prowler)
        if ((inst.instanceType ?? 'CLOUD_SQL_INSTANCE') === 'CLOUD_SQL_INSTANCE') {
          const cmekKeyName = inst.diskEncryptionConfiguration?.kmsKeyName;
          if (!cmekKeyName) {
            findings.push(this.emit(
              'cloudsql_instance_cmek_encryption_enabled',
              { instance: name, project },
              { message: `Cloud SQL instance "${name}" is not encrypted with a customer-managed key (CMEK); the Google-managed key is in use.` },
            ));
          }
        }

        // Database flags — security-relevant settings
        const flags = settings.databaseFlags ?? [];
        const flagMap = Object.fromEntries(flags.map((f: any) => [f.name, f.value]));

        // PostgreSQL flag checks
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

          // cloudsql_instance_postgres_enable_pgaudit_flag
          if (flagMap['cloudsql.enable_pgaudit'] !== 'on') {
            findings.push(this.emit(
              'cloudsql_instance_postgres_enable_pgaudit_flag',
              { instance: name, project, flag: 'cloudsql.enable_pgaudit', value: flagMap['cloudsql.enable_pgaudit'] ?? 'off' },
              { message: `PostgreSQL instance "${name}" does not have the 'cloudsql.enable_pgaudit' flag set to 'on'. Database activity lacks granular audit trails.` },
            ));
          }

          // cloudsql_instance_postgres_log_error_verbosity_flag — expected 'default'
          if ((flagMap['log_error_verbosity'] ?? 'default') !== 'default') {
            findings.push(this.emit(
              'cloudsql_instance_postgres_log_error_verbosity_flag',
              { instance: name, project, flag: 'log_error_verbosity', value: flagMap['log_error_verbosity'] },
              { message: `PostgreSQL instance "${name}" does not have 'log_error_verbosity' set to 'default' (found '${flagMap['log_error_verbosity']}').` },
            ));
          }

          // cloudsql_instance_postgres_log_min_duration_statement_flag — expected '-1'
          if ((flagMap['log_min_duration_statement'] ?? '-1') !== '-1') {
            findings.push(this.emit(
              'cloudsql_instance_postgres_log_min_duration_statement_flag',
              { instance: name, project, flag: 'log_min_duration_statement', value: flagMap['log_min_duration_statement'] },
              { message: `PostgreSQL instance "${name}" does not have 'log_min_duration_statement' set to '-1' (found '${flagMap['log_min_duration_statement']}'). Statement-duration logging can capture full SQL text, including literals, into log storage.` },
            ));
          }

          // cloudsql_instance_postgres_log_min_error_statement_flag — expected 'error'
          if ((flagMap['log_min_error_statement'] ?? 'error') !== 'error') {
            findings.push(this.emit(
              'cloudsql_instance_postgres_log_min_error_statement_flag',
              { instance: name, project, flag: 'log_min_error_statement', value: flagMap['log_min_error_statement'] },
              { message: `PostgreSQL instance "${name}" does not have 'log_min_error_statement' set to 'error' (found '${flagMap['log_min_error_statement']}').` },
            ));
          }

          // cloudsql_instance_postgres_log_min_messages_flag — must not be below ERROR
          {
            const failingLogLevels = ['DEBUG5', 'DEBUG4', 'DEBUG3', 'DEBUG2', 'DEBUG1', 'INFO', 'NOTICE'];
            const rawLevel = flagMap['log_min_messages'];
            const currentLevel = typeof rawLevel === 'string' ? rawLevel.toUpperCase() : undefined;
            if (!currentLevel || failingLogLevels.includes(currentLevel)) {
              findings.push(this.emit(
                'cloudsql_instance_postgres_log_min_messages_flag',
                { instance: name, project, flag: 'log_min_messages', value: rawLevel },
                {
                  message: currentLevel
                    ? `PostgreSQL instance "${name}" has 'log_min_messages' set to '${currentLevel}', which is below the recommended minimum of 'ERROR'.`
                    : `PostgreSQL instance "${name}" does not have the 'log_min_messages' flag set.`,
                },
              ));
            }
          }

          // cloudsql_instance_postgres_log_statement_flag — expected 'ddl'
          if (flagMap['log_statement'] !== 'ddl') {
            findings.push(this.emit(
              'cloudsql_instance_postgres_log_statement_flag',
              { instance: name, project, flag: 'log_statement', value: flagMap['log_statement'] ?? 'none' },
              { message: `PostgreSQL instance "${name}" does not have 'log_statement' set to 'ddl' (found '${flagMap['log_statement'] ?? 'none'}'). Schema-changing statements are not tracked.` },
            ));
          }
        }

        // MySQL flag checks
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

        // SQL Server flag checks
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

          // cloudsql_instance_sqlserver_external_scripts_enabled_flag — expected 'off'
          if ((flagMap['external scripts enabled'] ?? 'off') === 'on') {
            findings.push(this.emit(
              'cloudsql_instance_sqlserver_external_scripts_enabled_flag',
              { instance: name, project, flag: 'external scripts enabled' },
              { message: `SQL Server instance "${name}" does not have 'external scripts enabled' set to 'off'. Enabling external scripts lets SQL invoke language extensions (e.g. R/Python), risking arbitrary code execution.` },
            ));
          }

          // cloudsql_instance_sqlserver_remote_access_flag — expected 'off' (Prowler default-fails when flag absent)
          if ((flagMap['remote access'] ?? 'on') === 'on') {
            findings.push(this.emit(
              'cloudsql_instance_sqlserver_remote_access_flag',
              { instance: name, project, flag: 'remote access' },
              { message: `SQL Server instance "${name}" has 'remote access' set to 'on', allowing remote procedure calls between servers and expanding exposure.` },
            ));
          }

          // cloudsql_instance_sqlserver_trace_flag (3625) — expected 'on' (Prowler default-fails when flag absent)
          if ((flagMap['3625'] ?? 'off') !== 'on') {
            findings.push(this.emit(
              'cloudsql_instance_sqlserver_trace_flag',
              { instance: name, project, flag: '3625' },
              { message: `SQL Server instance "${name}" does not have trace flag 3625 set to 'on'. Without it, SQL errors can reveal parameters and object names to non-admins.` },
            ));
          }

          // cloudsql_instance_sqlserver_user_connections_flag — expected '0' (unlimited)
          if ((flagMap['user connections'] ?? '0') !== '0') {
            findings.push(this.emit(
              'cloudsql_instance_sqlserver_user_connections_flag',
              { instance: name, project, flag: 'user connections', value: flagMap['user connections'] },
              { message: `SQL Server instance "${name}" does not have 'user connections' set to '0' (unlimited); found '${flagMap['user connections']}'. A capped value can exhaust available sessions.` },
            ));
          }

          // cloudsql_instance_sqlserver_user_options_flag — expected unset/empty
          if ((flagMap['user options'] ?? '') !== '') {
            findings.push(this.emit(
              'cloudsql_instance_sqlserver_user_options_flag',
              { instance: name, project, flag: 'user options', value: flagMap['user options'] },
              { message: `SQL Server instance "${name}" has the 'user options' flag set, applying a global override to session SET behaviors that can produce inconsistent results.` },
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
        ['scanner-error'],
      ));
    }

    return findings;
  }
}
