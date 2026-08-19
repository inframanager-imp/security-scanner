// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  NeptuneClient,
  DescribeDBClustersCommand,
  DescribeDBClusterSnapshotsCommand,
  DescribeDBClusterSnapshotAttributesCommand,
  DescribeDBSubnetGroupsCommand,
} from '@aws-sdk/client-neptune';
import { EC2Client, DescribeRouteTablesCommand } from '@aws-sdk/client-ec2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const MINIMUM_BACKUP_RETENTION_PERIOD = 7;

export class NeptuneScanner extends BaseScanner {
  private neptune: NeptuneClient;
  private ec2: EC2Client;

  constructor(client: AWSClient) {
    super(client, 'Neptune');
    this.neptune = new NeptuneClient(client.getClientConfig());
    this.ec2 = new EC2Client(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Neptune security scan...');

      const clusters = await this.listClusters();
      for (const cluster of clusters) {
        const clusterName: string = cluster.DBClusterIdentifier ?? '';
        logger.debug(`Scanning Neptune cluster: ${clusterName}`);
        try {
          findings.push(...this.validateCluster(cluster));
        } catch (error) {
          logger.debug(`Failed to scan Neptune cluster ${clusterName}`, { error: (error as Error).message });
        }
        try {
          findings.push(...await this.validateClusterSubnets(cluster));
        } catch (error) {
          logger.debug(`Failed to check subnets for Neptune cluster ${clusterName}`, { error: (error as Error).message });
        }
      }

      const snapshots = await this.listClusterSnapshots();
      for (const snapshot of snapshots) {
        const snapshotId: string = snapshot.DBClusterSnapshotIdentifier ?? '';
        try {
          findings.push(...await this.validateSnapshot(snapshot));
        } catch (error) {
          logger.debug(`Failed to scan Neptune cluster snapshot ${snapshotId}`, { error: (error as Error).message });
        }
      }

      logger.info(`Neptune scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Neptune scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listClusters(): Promise<any[]> {
    const clusters: any[] = [];
    let marker: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.neptune.send(new DescribeDBClustersCommand({
          Filters: [{ Name: 'engine', Values: ['neptune'] }],
          Marker: marker,
        }));
      });
      clusters.push(...(result.DBClusters ?? []));
      marker = result.Marker;
    } while (marker);
    return clusters;
  }

  private async listClusterSnapshots(): Promise<any[]> {
    const snapshots: any[] = [];
    let marker: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.neptune.send(new DescribeDBClusterSnapshotsCommand({ Marker: marker }));
      });
      for (const snapshot of result.DBClusterSnapshots ?? []) {
        if (snapshot.Engine === 'neptune') {
          snapshots.push(snapshot);
        }
      }
      marker = result.Marker;
    } while (marker);
    return snapshots;
  }

  private validateCluster(cluster: any): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const clusterName: string = cluster.DBClusterIdentifier ?? '';
    const clusterArn: string = cluster.DBClusterArn ?? '';

    // neptune_cluster_storage_encrypted
    if (!(cluster.StorageEncrypted ?? false)) {
      findings.push(this.emit(
        'neptune_cluster_storage_encrypted',
        { cluster: clusterName, arn: clusterArn, storageEncrypted: false },
        {
          message: `Neptune cluster "${clusterName}" is not encrypted at rest`,
        }
      ));
    }

    // neptune_cluster_backup_enabled: retention >= 7 passes; 1-6 fails at LOW; 0 fails at default severity
    const backupRetentionPeriod: number = cluster.BackupRetentionPeriod ?? 0;
    if (backupRetentionPeriod < MINIMUM_BACKUP_RETENTION_PERIOD) {
      if (backupRetentionPeriod > 0) {
        findings.push(this.emit(
          'neptune_cluster_backup_enabled',
          { cluster: clusterName, arn: clusterArn, backupRetentionPeriod },
          {
            message: `Neptune cluster "${clusterName}" has backup enabled with a retention period of only ${backupRetentionPeriod} day(s); at least ${MINIMUM_BACKUP_RETENTION_PERIOD} days is recommended`,
            severity: 'LOW',
          }
        ));
      } else {
        findings.push(this.emit(
          'neptune_cluster_backup_enabled',
          { cluster: clusterName, arn: clusterArn, backupRetentionPeriod },
          {
            message: `Neptune cluster "${clusterName}" does not have automated backups enabled`,
          }
        ));
      }
    }

    // neptune_cluster_deletion_protection
    if (!(cluster.DeletionProtection ?? false)) {
      findings.push(this.emit(
        'neptune_cluster_deletion_protection',
        { cluster: clusterName, arn: clusterArn, deletionProtection: false },
        {
          message: `Neptune cluster "${clusterName}" does not have deletion protection enabled`,
        }
      ));
    }

    // neptune_cluster_iam_authentication_enabled
    if (!(cluster.IAMDatabaseAuthenticationEnabled ?? false)) {
      findings.push(this.emit(
        'neptune_cluster_iam_authentication_enabled',
        { cluster: clusterName, arn: clusterArn, iamDatabaseAuthenticationEnabled: false },
        {
          message: `Neptune cluster "${clusterName}" does not have IAM database authentication enabled`,
        }
      ));
    }

    // neptune_cluster_integration_cloudwatch_logs: audit log export required
    const cloudwatchLogs: string[] = cluster.EnabledCloudwatchLogsExports ?? [];
    if (!cloudwatchLogs.includes('audit')) {
      findings.push(this.emit(
        'neptune_cluster_integration_cloudwatch_logs',
        { cluster: clusterName, arn: clusterArn, enabledCloudwatchLogsExports: cloudwatchLogs },
        {
          message: `Neptune cluster "${clusterName}" does not export audit logs to CloudWatch Logs`,
        }
      ));
    }

    // neptune_cluster_multi_az
    if (!(cluster.MultiAZ ?? false)) {
      findings.push(this.emit(
        'neptune_cluster_multi_az',
        { cluster: clusterName, arn: clusterArn, multiAz: false },
        {
          message: `Neptune cluster "${clusterName}" does not have Multi-AZ enabled`,
        }
      ));
    }

    return findings;
  }

  // neptune_cluster_uses_public_subnet: any subnet of the DB subnet group whose
  // route table has a default route to an Internet gateway is public
  private async validateClusterSubnets(cluster: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const clusterName: string = cluster.DBClusterIdentifier ?? '';
    const clusterArn: string = cluster.DBClusterArn ?? '';
    const subnetGroupName: string = cluster.DBSubnetGroup ?? '';
    if (!subnetGroupName) return findings;

    const subnetGroupResult = await retry(async () => {
      return await this.neptune.send(new DescribeDBSubnetGroupsCommand({ DBSubnetGroupName: subnetGroupName }));
    });

    const publicSubnets: string[] = [];
    for (const subnetGroup of subnetGroupResult.DBSubnetGroups ?? []) {
      const vpcId: string = subnetGroup.VpcId ?? '';
      for (const subnet of subnetGroup.Subnets ?? []) {
        const subnetId: string = subnet.SubnetIdentifier ?? '';
        if (!subnetId) continue;
        try {
          if (await this.isSubnetPublic(subnetId, vpcId)) {
            publicSubnets.push(subnetId);
          }
        } catch (error) {
          logger.debug(`Failed to evaluate route tables for subnet ${subnetId}`, { error: (error as Error).message });
        }
      }
    }

    if (publicSubnets.length > 0) {
      findings.push(this.emit(
        'neptune_cluster_uses_public_subnet',
        { cluster: clusterName, arn: clusterArn, subnetGroup: subnetGroupName, publicSubnets },
        {
          message: `Neptune cluster "${clusterName}" is using public subnet(s): ${publicSubnets.join(', ')}`,
          remediation: `Move cluster "${clusterName}" to a DB subnet group containing only private subnets without Internet gateway routes`,
        }
      ));
    }

    return findings;
  }

  private async isSubnetPublic(subnetId: string, vpcId: string): Promise<boolean> {
    let routeTablesResult = await retry(async () => {
      return await this.ec2.send(new DescribeRouteTablesCommand({
        Filters: [{ Name: 'association.subnet-id', Values: [subnetId] }],
      }));
    });

    // A subnet with no explicit route table association uses the VPC main route table
    if (!routeTablesResult.RouteTables || routeTablesResult.RouteTables.length === 0) {
      const mainFilters: any[] = [{ Name: 'association.main', Values: ['true'] }];
      if (vpcId) {
        mainFilters.push({ Name: 'vpc-id', Values: [vpcId] });
      }
      routeTablesResult = await retry(async () => {
        return await this.ec2.send(new DescribeRouteTablesCommand({ Filters: mainFilters }));
      });
    }

    for (const routeTable of routeTablesResult.RouteTables ?? []) {
      for (const route of routeTable.Routes ?? []) {
        if (route.GatewayId && route.GatewayId.includes('igw') && route.DestinationCidrBlock === '0.0.0.0/0') {
          return true;
        }
      }
    }
    return false;
  }

  private async validateSnapshot(snapshot: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const snapshotId: string = snapshot.DBClusterSnapshotIdentifier ?? '';
    const clusterId: string = snapshot.DBClusterIdentifier ?? '';

    // neptune_cluster_snapshot_encrypted
    if (!(snapshot.StorageEncrypted ?? false)) {
      findings.push(this.emit(
        'neptune_cluster_snapshot_encrypted',
        { snapshot: snapshotId, cluster: clusterId, storageEncrypted: false },
        {
          message: `Neptune cluster snapshot "${snapshotId}" is not encrypted at rest`,
        }
      ));
    }

    // neptune_cluster_public_snapshot: restore attribute shared with "all"
    const attributesResult = await retry(async () => {
      return await this.neptune.send(new DescribeDBClusterSnapshotAttributesCommand({
        DBClusterSnapshotIdentifier: snapshotId,
      }));
    });
    const attributes: any[] = attributesResult.DBClusterSnapshotAttributesResult?.DBClusterSnapshotAttributes ?? [];
    const isPublic = attributes.some((att: any) => (att.AttributeValues ?? []).includes('all'));
    if (isPublic) {
      findings.push(this.emit(
        'neptune_cluster_public_snapshot',
        { snapshot: snapshotId, cluster: clusterId, sharedWith: 'all' },
        {
          message: `Neptune cluster snapshot "${snapshotId}" is shared publicly with all AWS accounts`,
          remediation: `Remove the "all" value from the restore attribute of snapshot "${snapshotId}" to make it private`,
        }
      ));
    }

    return findings;
  }
}

export default NeptuneScanner;
