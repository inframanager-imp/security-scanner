// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  DocDBClient,
  DescribeDBClustersCommand,
  DescribeDBClusterSnapshotsCommand,
  DescribeDBClusterSnapshotAttributesCommand,
} from '@aws-sdk/client-docdb';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const MINIMUM_BACKUP_RETENTION_PERIOD = 7;

export class DocumentDBScanner extends BaseScanner {
  private docdb: DocDBClient;

  constructor(client: AWSClient) {
    super(client, 'DocumentDB');
    this.docdb = new DocDBClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting DocumentDB security scan...');

      const clusters = await this.listClusters();
      for (const cluster of clusters) {
        const clusterId: string = cluster.DBClusterIdentifier ?? '';
        logger.debug(`Scanning DocumentDB cluster: ${clusterId}`);
        try {
          findings.push(...this.validateCluster(cluster));
        } catch (error) {
          logger.debug(`Failed to scan DocumentDB cluster ${clusterId}`, { error: (error as Error).message });
        }
      }

      const snapshots = await this.listClusterSnapshots();
      for (const snapshot of snapshots) {
        const snapshotId: string = snapshot.DBClusterSnapshotIdentifier ?? '';
        try {
          findings.push(...await this.validateSnapshot(snapshot));
        } catch (error) {
          logger.debug(`Failed to scan DocumentDB cluster snapshot ${snapshotId}`, { error: (error as Error).message });
        }
      }

      logger.info(`DocumentDB scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('DocumentDB scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listClusters(): Promise<any[]> {
    const clusters: any[] = [];
    let marker: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.docdb.send(new DescribeDBClustersCommand({
          Filters: [{ Name: 'engine', Values: ['docdb'] }],
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
        return await this.docdb.send(new DescribeDBClusterSnapshotsCommand({ Marker: marker }));
      });
      for (const snapshot of result.DBClusterSnapshots ?? []) {
        if (snapshot.Engine === 'docdb') {
          snapshots.push(snapshot);
        }
      }
      marker = result.Marker;
    } while (marker);
    return snapshots;
  }

  private validateCluster(cluster: any): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const clusterId: string = cluster.DBClusterIdentifier ?? '';
    const clusterArn: string = cluster.DBClusterArn ?? '';

    // documentdb_cluster_storage_encrypted
    if (!(cluster.StorageEncrypted ?? false)) {
      findings.push(this.emit(
        'documentdb_cluster_storage_encrypted',
        { cluster: clusterId, arn: clusterArn, storageEncrypted: false },
        {
          message: `DocumentDB cluster "${clusterId}" is not encrypted at rest`,
        }
      ));
    }

    // documentdb_cluster_backup_enabled: retention >= 7 passes; 1-6 fails at LOW; 0 fails at default severity
    const backupRetentionPeriod: number = cluster.BackupRetentionPeriod ?? 0;
    if (backupRetentionPeriod < MINIMUM_BACKUP_RETENTION_PERIOD) {
      if (backupRetentionPeriod > 0) {
        findings.push(this.emit(
          'documentdb_cluster_backup_enabled',
          { cluster: clusterId, arn: clusterArn, backupRetentionPeriod },
          {
            message: `DocumentDB cluster "${clusterId}" has backup enabled with a retention period of only ${backupRetentionPeriod} day(s); at least ${MINIMUM_BACKUP_RETENTION_PERIOD} days is recommended`,
            severity: 'LOW',
          }
        ));
      } else {
        findings.push(this.emit(
          'documentdb_cluster_backup_enabled',
          { cluster: clusterId, arn: clusterArn, backupRetentionPeriod },
          {
            message: `DocumentDB cluster "${clusterId}" does not have automated backups enabled`,
          }
        ));
      }
    }

    // documentdb_cluster_cloudwatch_log_export: both audit and profiler exports required;
    // partial coverage fails at LOW, none at default severity
    const cloudwatchLogs: string[] = cluster.EnabledCloudwatchLogsExports ?? [];
    const hasAudit = cloudwatchLogs.includes('audit');
    const hasProfiler = cloudwatchLogs.includes('profiler');
    if (!(hasAudit && hasProfiler)) {
      if (hasAudit || hasProfiler) {
        findings.push(this.emit(
          'documentdb_cluster_cloudwatch_log_export',
          { cluster: clusterId, arn: clusterArn, enabledCloudwatchLogsExports: cloudwatchLogs },
          {
            message: `DocumentDB cluster "${clusterId}" is only shipping ${cloudwatchLogs.join(', ')} to CloudWatch Logs; both audit and profiler logs are recommended`,
            severity: 'LOW',
          }
        ));
      } else {
        findings.push(this.emit(
          'documentdb_cluster_cloudwatch_log_export',
          { cluster: clusterId, arn: clusterArn, enabledCloudwatchLogsExports: cloudwatchLogs },
          {
            message: `DocumentDB cluster "${clusterId}" does not export audit or profiler logs to CloudWatch Logs`,
          }
        ));
      }
    }

    // documentdb_cluster_deletion_protection
    if (!(cluster.DeletionProtection ?? false)) {
      findings.push(this.emit(
        'documentdb_cluster_deletion_protection',
        { cluster: clusterId, arn: clusterArn, deletionProtection: false },
        {
          message: `DocumentDB cluster "${clusterId}" does not have deletion protection enabled`,
        }
      ));
    }

    // documentdb_cluster_multi_az_enabled
    if (!(cluster.MultiAZ ?? false)) {
      findings.push(this.emit(
        'documentdb_cluster_multi_az_enabled',
        { cluster: clusterId, arn: clusterArn, multiAz: false },
        {
          message: `DocumentDB cluster "${clusterId}" does not have Multi-AZ enabled`,
        }
      ));
    }

    return findings;
  }

  private async validateSnapshot(snapshot: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const snapshotId: string = snapshot.DBClusterSnapshotIdentifier ?? '';
    const clusterId: string = snapshot.DBClusterIdentifier ?? '';

    // documentdb_cluster_public_snapshot: restore attribute shared with "all"
    const attributesResult = await retry(async () => {
      return await this.docdb.send(new DescribeDBClusterSnapshotAttributesCommand({
        DBClusterSnapshotIdentifier: snapshotId,
      }));
    });
    const attributes: any[] = attributesResult.DBClusterSnapshotAttributesResult?.DBClusterSnapshotAttributes ?? [];
    const isPublic = attributes.some((att: any) => (att.AttributeValues ?? []).includes('all'));
    if (isPublic) {
      findings.push(this.emit(
        'documentdb_cluster_public_snapshot',
        { snapshot: snapshotId, cluster: clusterId, sharedWith: 'all' },
        {
          message: `DocumentDB cluster snapshot "${snapshotId}" is shared publicly with all AWS accounts`,
          remediation: `Remove the "all" value from the restore attribute of snapshot "${snapshotId}" to make it private`,
        }
      ));
    }

    return findings;
  }
}

export default DocumentDBScanner;
