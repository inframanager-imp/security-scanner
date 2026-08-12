// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  DescribeDBInstancesCommand,
  DescribeDBClustersCommand,
  DescribeDBSnapshotsCommand,
  DescribeDBSnapshotAttributesCommand,
  DescribeDBClusterSnapshotsCommand,
  DescribeDBClusterSnapshotAttributesCommand,
  DescribeEventSubscriptionsCommand,
  DescribeCertificatesCommand,
  DescribeDBEngineVersionsCommand,
  DescribeDBParametersCommand,
  DescribeDBClusterParametersCommand,
} from '@aws-sdk/client-rds';
import { BackupClient, ListProtectedResourcesCommand } from '@aws-sdk/client-backup';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import { CheckSeverity } from '../checks/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Prowler's RDS service excludes DocumentDB resources that surface through the RDS API
const EXCLUDED_ENGINE = 'docdb';

const DEFAULT_ADMIN_USERNAMES = ['admin', 'postgres'];

const AURORA_ENGINES = ['aurora', 'aurora-mysql', 'aurora-postgresql'];

const IAM_AUTH_SUPPORTED_ENGINES = [
  'postgres',
  'aurora-postgresql',
  'mysql',
  'mariadb',
  'aurora-mysql',
  'aurora',
];

const CLUSTER_CLOUDWATCH_LOGS_ENGINES = ['aurora-mysql', 'aurora-postgresql', 'mysql', 'postgres'];

// Engines where transport encryption is enforced through a parameter group,
// split by which parameter controls it (rds.force_ssl vs require_secure_transport)
const TRANSPORT_SUPPORTED_ENGINES = [
  'sqlserver-se',
  'sqlserver-ee',
  'sqlserver-ex',
  'sqlserver-web',
  'postgres',
  'aurora-postgresql',
  'mysql',
  'mariadb',
  'aurora-mysql',
];
const FORCE_SSL_ENGINES = [
  'sqlserver-se',
  'sqlserver-ee',
  'sqlserver-ex',
  'sqlserver-web',
  'postgres',
  'aurora-postgresql',
];

// Well-known default listener ports per engine family
const DEFAULT_ENGINE_PORTS: Array<{ port: number; engines: string[] }> = [
  { port: 3306, engines: ['mysql', 'mariadb', 'aurora-mysql'] },
  { port: 5432, engines: ['postgres', 'aurora-postgresql'] },
  { port: 1521, engines: ['oracle'] },
  { port: 1433, engines: ['sqlserver'] },
  { port: 50000, engines: ['db2'] },
];

// Table-driven definitions for the four RDS event subscription coverage checks.
// A check passes when at least one enabled subscription of the source type covers
// all events (empty category list) or exactly the required categories.
interface EventSubscriptionCheck {
  checkId: string;
  sourceType: string;
  requiredCategories: string[];
  scope: 'instance' | 'cluster';
  label: string;
}

const EVENT_SUBSCRIPTION_CHECKS: EventSubscriptionCheck[] = [
  {
    checkId: 'rds_cluster_critical_event_subscription',
    sourceType: 'db-cluster',
    requiredCategories: ['maintenance', 'failure'],
    scope: 'cluster',
    label: 'DB clusters',
  },
  {
    checkId: 'rds_instance_critical_event_subscription',
    sourceType: 'db-instance',
    requiredCategories: ['maintenance', 'configuration change', 'failure'],
    scope: 'instance',
    label: 'DB instances',
  },
  {
    checkId: 'rds_instance_event_subscription_parameter_groups',
    sourceType: 'db-parameter-group',
    requiredCategories: ['configuration change'],
    scope: 'instance',
    label: 'DB parameter groups',
  },
  {
    checkId: 'rds_instance_event_subscription_security_groups',
    sourceType: 'db-security-group',
    requiredCategories: ['configuration change', 'failure'],
    scope: 'instance',
    label: 'DB security groups',
  },
];

function addMonths(base: Date, months: number): Date {
  const result = new Date(base.getTime());
  result.setMonth(result.getMonth() + months);
  return result;
}

function usesDefaultPort(port: number | undefined, engine: string): boolean {
  if (!port) return false;
  const entry = DEFAULT_ENGINE_PORTS.find((candidate) => candidate.port === port);
  if (!entry) return false;
  const normalizedEngine = engine.toLowerCase();
  return entry.engines.some((defaultEngine) => normalizedEngine.includes(defaultEngine));
}

export class RDSScanner extends BaseScanner {
  private backup: BackupClient;

  constructor(client: AWSClient) {
    super(client, 'RDS');
    this.backup = new BackupClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting RDS security scan...');

      const instances = await this.listDBInstances();
      for (const instance of instances) {
        const dbId = instance.DBInstanceIdentifier || 'Unknown';
        logger.debug(`Scanning RDS instance: ${dbId}`);

        const instanceFindings = await this.validateDBInstance(instance);
        findings.push(...instanceFindings);
      }

      const clusters = await this.listDBClusters();
      for (const cluster of clusters) {
        const clusterId = cluster.DBClusterIdentifier || 'Unknown';
        logger.debug(`Scanning RDS cluster: ${clusterId}`);

        const clusterFindings = await this.validateDBCluster(cluster);
        findings.push(...clusterFindings);
      }

      // ---- Checks ported from Prowler (DocumentDB resources excluded, as in Prowler) ----
      const rdsInstances = instances.filter((instance: any) => instance.Engine !== EXCLUDED_ENGINE);
      const rdsClusters = clusters.filter((cluster: any) => cluster.Engine !== EXCLUDED_ENGINE);

      const clustersById = new Map<string, any>();
      for (const cluster of rdsClusters) {
        if (cluster.DBClusterIdentifier) clustersById.set(cluster.DBClusterIdentifier, cluster);
      }

      const protectedResources = await this.listBackupProtectedResources();
      const certificates = await this.listCertificates();

      for (const instance of rdsInstances) {
        try {
          findings.push(...this.validateInstanceChecks(instance, clustersById, protectedResources));
          findings.push(...this.validateInstanceCertificate(instance, certificates));
        } catch (error) {
          logger.debug(`Failed extended checks for RDS instance ${instance.DBInstanceIdentifier}`, { error: (error as Error).message });
        }
      }

      for (const cluster of rdsClusters) {
        try {
          findings.push(...this.validateClusterChecks(cluster, protectedResources));
        } catch (error) {
          logger.debug(`Failed extended checks for RDS cluster ${cluster.DBClusterIdentifier}`, { error: (error as Error).message });
        }
      }

      findings.push(...(await this.validateDeprecatedEngineVersions(rdsInstances)));
      findings.push(...(await this.validateTransportEncryption(rdsInstances, rdsClusters)));

      const eventSubscriptions = await this.listEventSubscriptions();
      if (eventSubscriptions) {
        findings.push(...this.validateEventSubscriptionChecks(
          eventSubscriptions,
          rdsInstances.length > 0,
          rdsClusters.length > 0
        ));
      }

      findings.push(...(await this.validateSnapshots()));

      logger.info(`RDS scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('RDS scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listDBInstances(): Promise<any[]> {
    return retry(async () => {
      logger.debug('Fetching RDS instances...');
      const instances: any[] = [];
      let marker: string | undefined;

      do {
        const result = await this.client.rds.send(
          new DescribeDBInstancesCommand({ Marker: marker, MaxRecords: 100 })
        );
        instances.push(...(result.DBInstances || []));
        marker = result.Marker;
      } while (marker);

      return instances;
    });
  }

  private async listDBClusters(): Promise<any[]> {
    return retry(async () => {
      logger.debug('Fetching RDS clusters...');
      const clusters: any[] = [];
      let marker: string | undefined;

      do {
        const result = await this.client.rds.send(
          new DescribeDBClustersCommand({ Marker: marker, MaxRecords: 100 })
        );
        clusters.push(...(result.DBClusters || []));
        marker = result.Marker;
      } while (marker);

      return clusters;
    });
  }

  private async validateDBInstance(instance: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const dbId = instance.DBInstanceIdentifier || 'Unknown';

    // Check encryption
    if (!instance.StorageEncrypted) {
      findings.push(this.emit(
        'rds_instance_storage_encrypted',
        { dbId, storageEncrypted: instance.StorageEncrypted },
        {
          message: `Database instance "${dbId}" does not have storage encryption enabled`,
          remediation: `Enable encryption at rest for database instance "${dbId}"`,
        }
      ));
    }

    // Check backup retention
    if ((instance.BackupRetentionPeriod || 0) < 7) {
      findings.push(this.emit(
        'rds_instance_backup_enabled',
        { dbId, retentionDays: instance.BackupRetentionPeriod },
        {
          message: `Database instance "${dbId}" has only ${instance.BackupRetentionPeriod}-day backup retention`,
          remediation: `Increase backup retention to at least 7 days for instance "${dbId}"`,
        }
      ));
    }

    // Check public accessibility
    if (instance.PubliclyAccessible) {
      findings.push(this.emit(
        'rds_instance_no_public_access',
        { dbId, publiclyAccessible: instance.PubliclyAccessible },
        {
          message: `Database instance "${dbId}" is publicly accessible from the internet`,
          remediation: `Disable public accessibility for database instance "${dbId}" and use VPC endpoints`,
        }
      ));
    }

    // Check deletion protection
    if (!instance.DeletionProtection) {
      findings.push(this.emit(
        'rds_instance_deletion_protection',
        { dbId, deletionProtection: instance.DeletionProtection },
        {
          message: `Database instance "${dbId}" does not have deletion protection enabled`,
          remediation: `Enable deletion protection for database instance "${dbId}"`,
        }
      ));
    }

    // Check Multi-AZ
    if (!instance.MultiAZ) {
      findings.push(this.emit(
        'rds_instance_multi_az',
        { dbId, multiAz: instance.MultiAZ },
        {
          message: `Database instance "${dbId}" is not deployed across multiple availability zones`,
          remediation: `Enable Multi-AZ deployment for database instance "${dbId}" for high availability`,
        }
      ));
    }

    // Check copy tags to snapshot
    if (!instance.CopyTagsToSnapshot) {
      findings.push(this.emit(
        'rds_instance_copy_tags_to_snapshots',
        { dbId },
        {
          message: `Database instance "${dbId}" does not copy tags to snapshots`,
          remediation: `Enable copy tags to snapshot for database instance "${dbId}"`,
        }
      ));
    }

    return findings;
  }

  private async validateDBCluster(cluster: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const clusterId = cluster.DBClusterIdentifier || 'Unknown';

    // Check encryption
    if (!cluster.StorageEncrypted) {
      findings.push(this.emit(
        'rds_cluster_storage_encrypted',
        { clusterId, storageEncrypted: cluster.StorageEncrypted },
        {
          message: `Database cluster "${clusterId}" does not have storage encryption enabled`,
          remediation: `Enable encryption at rest for database cluster "${clusterId}"`,
        }
      ));
    }

    // Check backup retention
    if ((cluster.BackupRetentionPeriod || 0) < 7) {
      findings.push(this.emit(
        'rds_cluster_backup_retention',
        { clusterId, retentionDays: cluster.BackupRetentionPeriod },
        {
          message: `Database cluster "${clusterId}" has only ${cluster.BackupRetentionPeriod}-day backup retention`,
          remediation: `Increase backup retention to at least 7 days for cluster "${clusterId}"`,
        }
      ));
    }

    return findings;
  }

  /** Per-instance checks ported from Prowler that need no extra API calls. */
  private validateInstanceChecks(
    instance: any,
    clustersById: Map<string, any>,
    protectedResources: Set<string> | null
  ): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const dbId = instance.DBInstanceIdentifier || 'Unknown';
    const engine: string = instance.Engine || '';

    // rds_instance_enhanced_monitoring_enabled
    if (!instance.EnhancedMonitoringResourceArn) {
      findings.push(this.emit(
        'rds_instance_enhanced_monitoring_enabled',
        { dbId, enhancedMonitoring: false },
        {
          message: `Database instance "${dbId}" does not have enhanced monitoring enabled`,
          remediation: `Enable enhanced monitoring on instance "${dbId}" with a non-zero monitoring interval and a monitoring IAM role`,
        }
      ));
    }

    // rds_instance_minor_version_upgrade_enabled
    if (!instance.AutoMinorVersionUpgrade) {
      findings.push(this.emit(
        'rds_instance_minor_version_upgrade_enabled',
        { dbId, autoMinorVersionUpgrade: false },
        {
          message: `Database instance "${dbId}" does not have automatic minor version upgrades enabled`,
          remediation: `Enable auto minor version upgrade on instance "${dbId}" so engine security patches are applied during maintenance windows`,
        }
      ));
    }

    // rds_instance_integration_cloudwatch_logs
    if (!instance.EnabledCloudwatchLogsExports || instance.EnabledCloudwatchLogsExports.length === 0) {
      findings.push(this.emit(
        'rds_instance_integration_cloudwatch_logs',
        { dbId, enabledCloudwatchLogsExports: instance.EnabledCloudwatchLogsExports || [] },
        {
          message: `Database instance "${dbId}" does not export any logs to CloudWatch Logs`,
          remediation: `Enable at least one supported log export (e.g. error, general, slowquery, audit) on instance "${dbId}"`,
        }
      ));
    }

    // rds_instance_inside_vpc
    if (!instance.DBSubnetGroup?.VpcId) {
      findings.push(this.emit(
        'rds_instance_inside_vpc',
        { dbId, vpcId: null },
        {
          message: `Database instance "${dbId}" is not deployed inside a VPC`,
          remediation: `Assign a DB subnet group in a VPC (preferably private subnets across multiple AZs) to instance "${dbId}"`,
        }
      ));
    }

    // rds_instance_extended_support
    if (instance.EngineLifecycleSupport === 'open-source-rds-extended-support') {
      findings.push(this.emit(
        'rds_instance_extended_support',
        { dbId, engine, engineVersion: instance.EngineVersion, engineLifecycleSupport: instance.EngineLifecycleSupport },
        {
          message: `Database instance "${dbId}" (${engine} ${instance.EngineVersion}) is enrolled in RDS Extended Support, which incurs additional charges`,
          remediation: `Upgrade instance "${dbId}" to an engine version under standard support, or explicitly disable Extended Support enrollment for new instances`,
        }
      ));
    }

    // rds_instance_default_admin (cluster members are governed by the cluster master username)
    if (instance.DBClusterIdentifier) {
      const cluster = clustersById.get(instance.DBClusterIdentifier);
      if (!cluster || DEFAULT_ADMIN_USERNAMES.includes(cluster.MasterUsername)) {
        findings.push(this.emit(
          'rds_instance_default_admin',
          { dbId, clusterId: instance.DBClusterIdentifier },
          {
            message: `Database instance "${dbId}" uses a default master username at cluster "${instance.DBClusterIdentifier}" level`,
            remediation: `Recreate cluster "${instance.DBClusterIdentifier}" with a custom, non-default master username and migrate workloads to it`,
          }
        ));
      }
    } else if (DEFAULT_ADMIN_USERNAMES.includes(instance.MasterUsername)) {
      findings.push(this.emit(
        'rds_instance_default_admin',
        { dbId, masterUsername: instance.MasterUsername },
        {
          message: `Database instance "${dbId}" uses the default master username "${instance.MasterUsername}"`,
          remediation: `Recreate instance "${dbId}" with a custom, non-default master username and migrate workloads to it`,
        }
      ));
    }

    // rds_instance_iam_authentication_enabled (supported engines only)
    if (
      IAM_AUTH_SUPPORTED_ENGINES.some((supported) => engine.includes(supported)) &&
      !instance.IAMDatabaseAuthenticationEnabled
    ) {
      const scopeNote = instance.DBClusterIdentifier ? ` at cluster "${instance.DBClusterIdentifier}" level` : '';
      findings.push(this.emit(
        'rds_instance_iam_authentication_enabled',
        { dbId, engine, iamDatabaseAuthenticationEnabled: false, clusterId: instance.DBClusterIdentifier || null },
        {
          message: `Database instance "${dbId}" does not have IAM database authentication enabled${scopeNote}`,
          remediation: `Enable IAM database authentication on instance "${dbId}"${scopeNote ? ' via its cluster' : ''} and grant scoped rds-db:connect permissions`,
        }
      ));
    }

    // rds_instance_non_default_port
    const port: number | undefined = instance.Endpoint?.Port;
    if (usesDefaultPort(port, engine)) {
      findings.push(this.emit(
        'rds_instance_non_default_port',
        { dbId, engine, port },
        {
          message: `Database instance "${dbId}" listens on the default port ${port} for engine ${engine}`,
          remediation: `Change the port of instance "${dbId}" to a non-default value and update connection strings and security group rules`,
        }
      ));
    }

    // rds_instance_protected_by_backup_plan (Aurora members are covered by the cluster check)
    if (protectedResources && !AURORA_ENGINES.includes(engine)) {
      const arn: string = instance.DBInstanceArn || '';
      const partition = arn.split(':')[1] || 'aws';
      const isProtected =
        (arn !== '' && protectedResources.has(arn)) ||
        protectedResources.has(`arn:${partition}:rds:*:*:instance:*`) ||
        protectedResources.has('*');
      if (!isProtected) {
        findings.push(this.emit(
          'rds_instance_protected_by_backup_plan',
          { dbId, arn },
          {
            message: `Database instance "${dbId}" is not protected by any AWS Backup plan`,
            remediation: `Assign instance "${dbId}" to an AWS Backup plan, directly, by tag, or via a resource wildcard selection`,
          }
        ));
      }
    }

    return findings;
  }

  /** rds_instance_certificate_expiration: fail when the CA certificate has under 3 months of validity. */
  private validateInstanceCertificate(instance: any, certificates: Map<string, any>): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const dbId = instance.DBInstanceIdentifier || 'Unknown';
    const certificateId: string | undefined = instance.CACertificateIdentifier;
    if (!certificateId) return findings;

    const certificate = certificates.get(certificateId);
    if (!certificate || !certificate.ValidTill) return findings;

    const validTill = new Date(certificate.ValidTill);
    const now = new Date();
    if (validTill >= addMonths(now, 3)) return findings;

    let message: string;
    let severity: CheckSeverity;
    if (validTill <= now) {
      message = `Database instance "${dbId}" CA certificate "${certificateId}" has expired`;
      severity = 'CRITICAL';
    } else if (validTill < addMonths(now, 1)) {
      message = `Database instance "${dbId}" CA certificate "${certificateId}" expires in less than 1 month`;
      severity = 'HIGH';
    } else {
      message = `Database instance "${dbId}" CA certificate "${certificateId}" expires in less than 3 months`;
      severity = 'MEDIUM';
    }

    findings.push(this.emit(
      'rds_instance_certificate_expiration',
      { dbId, certificateId, validTill: validTill.toISOString() },
      {
        message,
        severity,
        remediation: `Rotate the CA certificate of instance "${dbId}" to a current authority (e.g. rds-ca-rsa2048-g1) and update client trust stores`,
      }
    ));

    return findings;
  }

  /** Per-cluster checks ported from Prowler that need no extra API calls. */
  private validateClusterChecks(cluster: any, protectedResources: Set<string> | null): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const clusterId = cluster.DBClusterIdentifier || 'Unknown';
    const engine: string = cluster.Engine || '';

    // rds_cluster_backtrack_enabled (only Aurora MySQL supports Backtrack)
    if (engine === 'aurora-mysql' && !((cluster.BacktrackWindow || 0) > 0)) {
      findings.push(this.emit(
        'rds_cluster_backtrack_enabled',
        { clusterId, engine, backtrackWindow: cluster.BacktrackWindow || 0 },
        {
          message: `Database cluster "${clusterId}" does not have Backtrack enabled`,
          remediation: `Enable Backtrack on cluster "${clusterId}" with a backtrack window that meets your recovery objectives (e.g. 3600 seconds)`,
        }
      ));
    }

    // rds_cluster_copy_tags_to_snapshots
    if (!cluster.CopyTagsToSnapshot) {
      findings.push(this.emit(
        'rds_cluster_copy_tags_to_snapshots',
        { clusterId },
        {
          message: `Database cluster "${clusterId}" does not copy tags to snapshots`,
          remediation: `Enable copy tags to snapshot for database cluster "${clusterId}"`,
        }
      ));
    }

    // rds_cluster_default_admin
    if (DEFAULT_ADMIN_USERNAMES.includes(cluster.MasterUsername)) {
      findings.push(this.emit(
        'rds_cluster_default_admin',
        { clusterId, masterUsername: cluster.MasterUsername },
        {
          message: `Database cluster "${clusterId}" uses the default master username "${cluster.MasterUsername}"`,
          remediation: `Recreate cluster "${clusterId}" with a custom, non-default master username and migrate workloads to it`,
        }
      ));
    }

    // rds_cluster_deletion_protection
    if (!cluster.DeletionProtection) {
      findings.push(this.emit(
        'rds_cluster_deletion_protection',
        { clusterId, deletionProtection: false },
        {
          message: `Database cluster "${clusterId}" does not have deletion protection enabled`,
          remediation: `Enable deletion protection for database cluster "${clusterId}"`,
        }
      ));
    }

    // rds_cluster_iam_authentication_enabled (supported engines only)
    if (
      IAM_AUTH_SUPPORTED_ENGINES.some((supported) => engine.includes(supported)) &&
      !cluster.IAMDatabaseAuthenticationEnabled
    ) {
      findings.push(this.emit(
        'rds_cluster_iam_authentication_enabled',
        { clusterId, engine, iamDatabaseAuthenticationEnabled: false },
        {
          message: `Database cluster "${clusterId}" does not have IAM database authentication enabled`,
          remediation: `Enable IAM database authentication on cluster "${clusterId}" and grant scoped rds-db:connect permissions`,
        }
      ));
    }

    // rds_cluster_integration_cloudwatch_logs (supported engines only)
    if (
      CLUSTER_CLOUDWATCH_LOGS_ENGINES.includes(engine) &&
      (!cluster.EnabledCloudwatchLogsExports || cluster.EnabledCloudwatchLogsExports.length === 0)
    ) {
      findings.push(this.emit(
        'rds_cluster_integration_cloudwatch_logs',
        { clusterId, engine, enabledCloudwatchLogsExports: cluster.EnabledCloudwatchLogsExports || [] },
        {
          message: `Database cluster "${clusterId}" does not export any logs to CloudWatch Logs`,
          remediation: `Enable at least one supported log export (e.g. error, audit, postgresql) on cluster "${clusterId}"`,
        }
      ));
    }

    // rds_cluster_minor_version_upgrade_enabled (only Multi-AZ DB clusters expose this setting)
    if (cluster.MultiAZ && !cluster.AutoMinorVersionUpgrade) {
      findings.push(this.emit(
        'rds_cluster_minor_version_upgrade_enabled',
        { clusterId, autoMinorVersionUpgrade: false },
        {
          message: `Database cluster "${clusterId}" does not have automatic minor version upgrades enabled`,
          remediation: `Enable auto minor version upgrade on cluster "${clusterId}" so engine security patches are applied during maintenance windows`,
        }
      ));
    }

    // rds_cluster_multi_az
    if (!cluster.MultiAZ) {
      findings.push(this.emit(
        'rds_cluster_multi_az',
        { clusterId, multiAz: false },
        {
          message: `Database cluster "${clusterId}" is not deployed across multiple availability zones`,
          remediation: `Enable Multi-AZ deployment for database cluster "${clusterId}" for high availability`,
        }
      ));
    }

    // rds_cluster_non_default_port
    if (usesDefaultPort(cluster.Port, engine)) {
      findings.push(this.emit(
        'rds_cluster_non_default_port',
        { clusterId, engine, port: cluster.Port },
        {
          message: `Database cluster "${clusterId}" listens on the default port ${cluster.Port} for engine ${engine}`,
          remediation: `Change the port of cluster "${clusterId}" to a non-default value and update connection strings and security group rules`,
        }
      ));
    }

    // rds_cluster_protected_by_backup_plan
    if (protectedResources) {
      const arn: string = cluster.DBClusterArn || '';
      const partition = arn.split(':')[1] || 'aws';
      const isProtected =
        (arn !== '' && protectedResources.has(arn)) ||
        protectedResources.has(`arn:${partition}:rds:*:*:cluster:*`) ||
        protectedResources.has('*');
      if (!isProtected) {
        findings.push(this.emit(
          'rds_cluster_protected_by_backup_plan',
          { clusterId, arn },
          {
            message: `Database cluster "${clusterId}" is not protected by any AWS Backup plan`,
            remediation: `Assign cluster "${clusterId}" to an AWS Backup plan, directly, by tag, or via a resource wildcard selection`,
          }
        ));
      }
    }

    return findings;
  }

  /** rds_instance_deprecated_engine_version: engine version no longer listed as available in the region. */
  private async validateDeprecatedEngineVersions(instances: any[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    if (instances.length === 0) return findings;

    const engines = [...new Set(instances.map((instance: any) => instance.Engine).filter(Boolean))] as string[];
    const availableVersions = new Map<string, Set<string>>();

    for (const engine of engines) {
      try {
        const versions = new Set<string>();
        let marker: string | undefined;
        do {
          const result: any = await retry(async () => {
            return await this.client.rds.send(
              new DescribeDBEngineVersionsCommand({ Engine: engine, Marker: marker, MaxRecords: 100 })
            );
          });
          for (const engineVersion of result.DBEngineVersions || []) {
            if (engineVersion.EngineVersion) versions.add(engineVersion.EngineVersion);
          }
          marker = result.Marker;
        } while (marker);
        availableVersions.set(engine, versions);
      } catch (error) {
        logger.debug(`Failed to describe available engine versions for ${engine}`, { error: (error as Error).message });
      }
    }

    for (const instance of instances) {
      const versions = availableVersions.get(instance.Engine);
      if (!versions) continue; // lookup failed; skip rather than emit a false positive
      if (!versions.has(instance.EngineVersion)) {
        const dbId = instance.DBInstanceIdentifier || 'Unknown';
        findings.push(this.emit(
          'rds_instance_deprecated_engine_version',
          { dbId, engine: instance.Engine, engineVersion: instance.EngineVersion },
          {
            message: `Database instance "${dbId}" runs ${instance.Engine} ${instance.EngineVersion}, which is no longer an available engine version in this region`,
            remediation: `Upgrade instance "${dbId}" to a currently supported ${instance.Engine} version, testing the upgrade in non-production first`,
          }
        ));
      }
    }

    return findings;
  }

  /**
   * rds_instance_transport_encrypted: SSL/TLS enforcement via parameter groups.
   * Prowler evaluates standalone instances (rds.force_ssl / require_secure_transport = 1)
   * and clusters (rds.force_ssl = 1 or require_secure_transport = ON) under this checkId.
   */
  private async validateTransportEncryption(instances: any[], clusters: any[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    for (const instance of instances) {
      const dbId = instance.DBInstanceIdentifier || 'Unknown';
      const engine: string = instance.Engine || '';
      // Cluster members are governed by the cluster parameter group (checked below)
      if (instance.DBClusterIdentifier) continue;
      if (!TRANSPORT_SUPPORTED_ENGINES.some((supported) => engine.includes(supported))) continue;

      const parameterName = FORCE_SSL_ENGINES.includes(engine) ? 'rds.force_ssl' : 'require_secure_transport';
      const parameterGroups: string[] = (instance.DBParameterGroups || [])
        .map((group: any) => group.DBParameterGroupName)
        .filter(Boolean);

      try {
        let enforced = false;
        for (const groupName of parameterGroups) {
          const value = await this.findDBParameterValue(groupName, parameterName);
          if (value === '1') {
            enforced = true;
            break;
          }
        }

        if (!enforced) {
          findings.push(this.emit(
            'rds_instance_transport_encrypted',
            { dbId, engine, parameter: parameterName, parameterGroups },
            {
              message: `Database instance "${dbId}" does not enforce encrypted SSL/TLS client connections`,
              remediation: `Set ${parameterName}=1 in the DB parameter group attached to instance "${dbId}" and reboot the instance if the parameter is static`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to evaluate transport encryption for RDS instance ${dbId}`, { error: (error as Error).message });
      }
    }

    for (const cluster of clusters) {
      const clusterId = cluster.DBClusterIdentifier || 'Unknown';
      const groupName: string | undefined = cluster.DBClusterParameterGroup;
      if (!groupName) continue;

      try {
        const values = await this.findDBClusterParameterValues(groupName, ['rds.force_ssl', 'require_secure_transport']);
        const enforced = values['rds.force_ssl'] === '1' || values['require_secure_transport'] === 'ON';
        if (!enforced) {
          findings.push(this.emit(
            'rds_instance_transport_encrypted',
            {
              clusterId,
              engine: cluster.Engine,
              parameterGroup: groupName,
              forceSsl: values['rds.force_ssl'] ?? null,
              requireSecureTransport: values['require_secure_transport'] ?? null,
            },
            {
              message: `Database cluster "${clusterId}" does not enforce encrypted SSL/TLS client connections`,
              remediation: `Set rds.force_ssl=1 (PostgreSQL) or require_secure_transport=ON (MySQL) in DB cluster parameter group "${groupName}" attached to cluster "${clusterId}"`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to evaluate transport encryption for RDS cluster ${clusterId}`, { error: (error as Error).message });
      }
    }

    return findings;
  }

  /** Table-driven event subscription coverage checks (one account/region-level finding per gap). */
  private validateEventSubscriptionChecks(
    subscriptions: any[],
    hasInstances: boolean,
    hasClusters: boolean
  ): ScanningResult[] {
    const findings: ScanningResult[] = [];

    for (const check of EVENT_SUBSCRIPTION_CHECKS) {
      // Prowler only evaluates these when matching resources exist in the account
      if (check.scope === 'cluster' ? !hasClusters : !hasInstances) continue;

      const enabledForSource = subscriptions.filter(
        (subscription: any) => subscription.SourceType === check.sourceType && subscription.Enabled
      );
      const satisfied = enabledForSource.some((subscription: any) => {
        const categories: string[] = subscription.EventCategoriesList || [];
        return (
          categories.length === 0 ||
          (categories.length === check.requiredCategories.length &&
            check.requiredCategories.every((category) => categories.includes(category)))
        );
      });

      if (!satisfied) {
        findings.push(this.emit(
          check.checkId,
          {
            sourceType: check.sourceType,
            requiredCategories: check.requiredCategories,
            enabledSubscriptions: enabledForSource.length,
          },
          {
            message: `No enabled RDS event subscription for ${check.label} covers the ${check.requiredCategories.join(', ')} event categories`,
            remediation: `Create an enabled RDS event subscription with source type "${check.sourceType}" covering the ${check.requiredCategories.join(', ')} event categories (or all events) and deliver notifications to a monitored SNS topic`,
          }
        ));
      }
    }

    return findings;
  }

  /** rds_snapshots_encrypted + rds_snapshots_public_access over DB and cluster snapshots. */
  private async validateSnapshots(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    let snapshots: any[] = [];
    try {
      snapshots = (await this.listDBSnapshots()).filter((snapshot: any) => snapshot.Engine !== EXCLUDED_ENGINE);
    } catch (error) {
      logger.debug('Failed to list RDS snapshots', { error: (error as Error).message });
    }

    for (const snapshot of snapshots) {
      const snapshotId = snapshot.DBSnapshotIdentifier || 'Unknown';

      if (!snapshot.Encrypted) {
        findings.push(this.emit(
          'rds_snapshots_encrypted',
          { snapshotId, instanceId: snapshot.DBInstanceIdentifier, encrypted: false },
          {
            message: `Database snapshot "${snapshotId}" is not encrypted at rest`,
            remediation: `Copy snapshot "${snapshotId}" with a KMS key to create an encrypted copy, then delete the unencrypted original`,
          }
        ));
      }

      try {
        if (await this.isDBSnapshotPublic(snapshotId)) {
          findings.push(this.emit(
            'rds_snapshots_public_access',
            { snapshotId, instanceId: snapshot.DBInstanceIdentifier, public: true },
            {
              message: `Database snapshot "${snapshotId}" is publicly restorable by any AWS account`,
              remediation: `Remove the "all" value from the restore attribute of snapshot "${snapshotId}" (modify-db-snapshot-attribute --attribute-name restore --values-to-remove all)`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to describe attributes for RDS snapshot ${snapshotId}`, { error: (error as Error).message });
      }
    }

    let clusterSnapshots: any[] = [];
    try {
      clusterSnapshots = (await this.listDBClusterSnapshots()).filter(
        (snapshot: any) => snapshot.Engine !== EXCLUDED_ENGINE
      );
    } catch (error) {
      logger.debug('Failed to list RDS cluster snapshots', { error: (error as Error).message });
    }

    for (const snapshot of clusterSnapshots) {
      const snapshotId = snapshot.DBClusterSnapshotIdentifier || 'Unknown';

      if (!snapshot.StorageEncrypted) {
        findings.push(this.emit(
          'rds_snapshots_encrypted',
          { snapshotId, clusterId: snapshot.DBClusterIdentifier, encrypted: false },
          {
            message: `Cluster snapshot "${snapshotId}" is not encrypted at rest`,
            remediation: `Copy cluster snapshot "${snapshotId}" with a KMS key to create an encrypted copy, then delete the unencrypted original`,
          }
        ));
      }

      try {
        if (await this.isDBClusterSnapshotPublic(snapshotId)) {
          findings.push(this.emit(
            'rds_snapshots_public_access',
            { snapshotId, clusterId: snapshot.DBClusterIdentifier, public: true },
            {
              message: `Cluster snapshot "${snapshotId}" is publicly restorable by any AWS account`,
              remediation: `Remove the "all" value from the restore attribute of cluster snapshot "${snapshotId}" (modify-db-cluster-snapshot-attribute --attribute-name restore --values-to-remove all)`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to describe attributes for RDS cluster snapshot ${snapshotId}`, { error: (error as Error).message });
      }
    }

    return findings;
  }

  private async listDBSnapshots(): Promise<any[]> {
    const snapshots: any[] = [];
    let marker: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.client.rds.send(new DescribeDBSnapshotsCommand({ Marker: marker, MaxRecords: 100 }));
      });
      snapshots.push(...(result.DBSnapshots || []));
      marker = result.Marker;
    } while (marker);
    return snapshots;
  }

  private async listDBClusterSnapshots(): Promise<any[]> {
    const snapshots: any[] = [];
    let marker: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.client.rds.send(new DescribeDBClusterSnapshotsCommand({ Marker: marker, MaxRecords: 100 }));
      });
      snapshots.push(...(result.DBClusterSnapshots || []));
      marker = result.Marker;
    } while (marker);
    return snapshots;
  }

  private async isDBSnapshotPublic(snapshotId: string): Promise<boolean> {
    const result: any = await retry(async () => {
      return await this.client.rds.send(
        new DescribeDBSnapshotAttributesCommand({ DBSnapshotIdentifier: snapshotId })
      );
    });
    const attributes: any[] = result.DBSnapshotAttributesResult?.DBSnapshotAttributes || [];
    return attributes.some((attribute: any) => (attribute.AttributeValues || []).includes('all'));
  }

  private async isDBClusterSnapshotPublic(snapshotId: string): Promise<boolean> {
    const result: any = await retry(async () => {
      return await this.client.rds.send(
        new DescribeDBClusterSnapshotAttributesCommand({ DBClusterSnapshotIdentifier: snapshotId })
      );
    });
    const attributes: any[] = result.DBClusterSnapshotAttributesResult?.DBClusterSnapshotAttributes || [];
    return attributes.some((attribute: any) => (attribute.AttributeValues || []).includes('all'));
  }

  /** Returns null on API failure so event subscription checks are skipped instead of emitting false gaps. */
  private async listEventSubscriptions(): Promise<any[] | null> {
    try {
      const subscriptions: any[] = [];
      let marker: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.client.rds.send(
            new DescribeEventSubscriptionsCommand({ Marker: marker, MaxRecords: 100 })
          );
        });
        subscriptions.push(...(result.EventSubscriptionsList || []));
        marker = result.Marker;
      } while (marker);
      return subscriptions;
    } catch (error) {
      logger.debug('Failed to describe RDS event subscriptions; skipping event subscription checks', { error: (error as Error).message });
      return null;
    }
  }

  /** All RDS CA certificates in the region, keyed by CertificateIdentifier. Empty map on failure. */
  private async listCertificates(): Promise<Map<string, any>> {
    const certificates = new Map<string, any>();
    try {
      let marker: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.client.rds.send(new DescribeCertificatesCommand({ Marker: marker, MaxRecords: 100 }));
        });
        for (const certificate of result.Certificates || []) {
          if (certificate.CertificateIdentifier) certificates.set(certificate.CertificateIdentifier, certificate);
        }
        marker = result.Marker;
      } while (marker);
    } catch (error) {
      logger.debug('Failed to describe RDS certificates; skipping certificate expiration check', { error: (error as Error).message });
    }
    return certificates;
  }

  /** ARNs protected by AWS Backup. Returns null on failure so backup-plan checks are skipped. */
  private async listBackupProtectedResources(): Promise<Set<string> | null> {
    try {
      const resources = new Set<string>();
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.backup.send(new ListProtectedResourcesCommand({ NextToken: nextToken }));
        });
        for (const resource of result.Results || []) {
          if (resource.ResourceArn) resources.add(resource.ResourceArn);
        }
        nextToken = result.NextToken;
      } while (nextToken);
      return resources;
    } catch (error) {
      logger.debug('Failed to list AWS Backup protected resources; skipping backup-plan protection checks', { error: (error as Error).message });
      return null;
    }
  }

  /** Scans a DB parameter group (paginated) for a single parameter's value. */
  private async findDBParameterValue(groupName: string, parameterName: string): Promise<string | undefined> {
    let marker: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.client.rds.send(
          new DescribeDBParametersCommand({ DBParameterGroupName: groupName, Marker: marker, MaxRecords: 100 })
        );
      });
      for (const parameter of result.Parameters || []) {
        if (parameter.ParameterName === parameterName) return parameter.ParameterValue;
      }
      marker = result.Marker;
    } while (marker);
    return undefined;
  }

  /** Scans a DB cluster parameter group (paginated) for the requested parameter values. */
  private async findDBClusterParameterValues(
    groupName: string,
    parameterNames: string[]
  ): Promise<Record<string, string>> {
    const values: Record<string, string> = {};
    let marker: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.client.rds.send(
          new DescribeDBClusterParametersCommand({
            DBClusterParameterGroupName: groupName,
            Marker: marker,
            MaxRecords: 100,
          })
        );
      });
      for (const parameter of result.Parameters || []) {
        if (
          parameter.ParameterName &&
          parameterNames.includes(parameter.ParameterName) &&
          parameter.ParameterValue !== undefined
        ) {
          values[parameter.ParameterName] = parameter.ParameterValue;
        }
      }
      if (Object.keys(values).length === parameterNames.length) break;
      marker = result.Marker;
    } while (marker);
    return values;
  }
}

export default RDSScanner;
