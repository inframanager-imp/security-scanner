import {
  DescribeDBInstancesCommand,
  DescribeDBClustersCommand
} from '@aws-sdk/client-rds';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class RDSScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'RDS');
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
}

export default RDSScanner;
