import {
  DescribeClustersCommand,
  DescribeLoggingStatusCommand,
  type Cluster,
} from '@aws-sdk/client-redshift';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const DEFAULT_ADMIN_USERNAMES = new Set(['awsuser', 'admin', 'master', 'redshift', 'root']);

export class RedshiftScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'Redshift');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting Redshift security scan...');

    const clusters = await this.listClusters();
    logger.info(`Redshift: scanning ${clusters.length} cluster(s)`);

    for (const cluster of clusters) {
      findings.push(...(await this.scanCluster(cluster)));
    }

    logger.info(`Redshift scan complete. ${findings.length} findings.`);
    return findings;
  }

  private async listClusters(): Promise<Cluster[]> {
    const clusters: Cluster[] = [];
    let marker: string | undefined;
    try {
      do {
        const result = await retry(() =>
          this.client.redshift.send(new DescribeClustersCommand({ Marker: marker, MaxRecords: 100 }))
        );
        clusters.push(...(result.Clusters ?? []));
        marker = result.Marker;
      } while (marker);
    } catch { /* no permission */ }
    return clusters;
  }

  private async scanCluster(cluster: Cluster): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const id  = cluster.ClusterIdentifier ?? 'Unknown';
    const arn = cluster.ClusterNamespaceArn ?? id;

    // 1. Publicly accessible
    if (cluster.PubliclyAccessible) {
      findings.push(this.createFinding(
        'Redshift Cluster Publicly Accessible',
        `Redshift cluster "${id}" is configured as publicly accessible. ` +
        `The cluster endpoint can be reached from the internet, exposing it to brute force and vulnerability exploits.`,
        'CRITICAL',
        { resourceId: arn, clusterId: id, endpoint: cluster.Endpoint?.Address },
        `Disable public accessibility: aws redshift modify-cluster --cluster-identifier ${id} --no-publicly-accessible. ` +
        `Access the cluster via a VPC bastion or VPN only.`,
        ['redshift', 'network', 'public-access'],
      ));
    }

    // 2. Encryption disabled
    if (!cluster.Encrypted) {
      findings.push(this.createFinding(
        'Redshift Cluster Not Encrypted',
        `Redshift cluster "${id}" does not have encryption at rest enabled. ` +
        `All data stored on cluster nodes, backups, and snapshots is unencrypted.`,
        'HIGH',
        { resourceId: `${arn}::encryption`, clusterId: id },
        `Enable encryption by restoring the cluster from a snapshot with encryption enabled, ` +
        `or create a new encrypted cluster and migrate data.`,
        ['redshift', 'encryption'],
      ));
    }

    // 3. Audit logging
    try {
      const logging = await retry(() =>
        this.client.redshift.send(new DescribeLoggingStatusCommand({ ClusterIdentifier: id }))
      );
      if (!logging.LoggingEnabled) {
        findings.push(this.createFinding(
          'Redshift Cluster Audit Logging Disabled',
          `Redshift cluster "${id}" does not have audit logging enabled. ` +
          `Connection attempts, user activity, and queries are not being logged for security review.`,
          'HIGH',
          { resourceId: `${arn}::logging`, clusterId: id },
          `Enable audit logging: aws redshift enable-logging --cluster-identifier ${id} ` +
          `--bucket-name <s3-bucket> --s3-key-prefix redshift-logs/`,
          ['redshift', 'logging', 'audit'],
        ));
      }
    } catch { /* no permission for logging status */ }

    // 4. Default admin username
    const masterUser = cluster.MasterUsername ?? '';
    if (DEFAULT_ADMIN_USERNAMES.has(masterUser.toLowerCase())) {
      findings.push(this.createFinding(
        'Redshift Cluster Uses Default Admin Username',
        `Redshift cluster "${id}" uses the default admin username "${masterUser}". ` +
        `Default usernames are well-known and make brute force attacks easier.`,
        'MEDIUM',
        { resourceId: `${arn}::admin-user`, clusterId: id, masterUsername: masterUser },
        `Create a new admin user with a non-default username, grant necessary permissions, then remove the default admin user.`,
        ['redshift', 'authentication'],
      ));
    }

    // 5. Not in VPC
    if (!cluster.VpcId) {
      findings.push(this.createFinding(
        'Redshift Cluster Not in VPC',
        `Redshift cluster "${id}" is not running inside a VPC. ` +
        `Clusters outside VPC lack network isolation and cannot use VPC security groups or endpoints.`,
        'HIGH',
        { resourceId: `${arn}::vpc`, clusterId: id },
        `Migrate the cluster to a VPC. Create a new cluster in a VPC subnet group and restore from snapshot.`,
        ['redshift', 'network'],
      ));
    }

    // 6. Automated snapshots disabled
    if ((cluster.AutomatedSnapshotRetentionPeriod ?? 0) === 0) {
      findings.push(this.createFinding(
        'Redshift Cluster Automated Snapshots Disabled',
        `Redshift cluster "${id}" has automated snapshot retention set to 0 (disabled). ` +
        `Data cannot be recovered from automated backups in the event of accidental deletion or corruption.`,
        'HIGH',
        { resourceId: `${arn}::snapshots`, clusterId: id },
        `Enable automated snapshots: aws redshift modify-cluster --cluster-identifier ${id} --automated-snapshot-retention-period 7`,
        ['redshift', 'backup'],
      ));
    }

    // 7. Enhanced VPC routing disabled (data stays in VPC)
    if (cluster.VpcId && !cluster.EnhancedVpcRouting) {
      findings.push(this.createFinding(
        'Redshift Cluster Enhanced VPC Routing Disabled',
        `Redshift cluster "${id}" has Enhanced VPC Routing disabled. ` +
        `Without it, COPY and UNLOAD traffic travels over the internet instead of staying within the VPC.`,
        'MEDIUM',
        { resourceId: `${arn}::enhanced-vpc`, clusterId: id },
        `Enable enhanced VPC routing: aws redshift modify-cluster --cluster-identifier ${id} --enhanced-vpc-routing`,
        ['redshift', 'network'],
      ));
    }

    return findings;
  }
}

export default RedshiftScanner;
