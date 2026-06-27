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
      findings.push(this.createFinding(
        'RDS Not Encrypted',
        `Database instance "${dbId}" does not have storage encryption enabled`,
        'HIGH',
        { dbId, storageEncrypted: instance.StorageEncrypted },
        `Enable encryption at rest for database instance "${dbId}"`,
        ['rds', 'encryption', 'data-protection']
      ));
    }

    // Check backup retention
    if ((instance.BackupRetentionPeriod || 0) < 7) {
      findings.push(this.createFinding(
        'Short Backup Retention',
        `Database instance "${dbId}" has only ${instance.BackupRetentionPeriod}-day backup retention`,
        'MEDIUM',
        { dbId, retentionDays: instance.BackupRetentionPeriod },
        `Increase backup retention to at least 7 days for instance "${dbId}"`,
        ['rds', 'backup', 'disaster-recovery']
      ));
    }

    // Check public accessibility
    if (instance.PubliclyAccessible) {
      findings.push(this.createFinding(
        'Database Publicly Accessible',
        `Database instance "${dbId}" is publicly accessible from the internet`,
        'CRITICAL',
        { dbId, publiclyAccessible: instance.PubliclyAccessible },
        `Disable public accessibility for database instance "${dbId}" and use VPC endpoints`,
        ['rds', 'public-access', 'network']
      ));
    }

    // Check deletion protection
    if (!instance.DeletionProtection) {
      findings.push(this.createFinding(
        'Deletion Protection Not Enabled',
        `Database instance "${dbId}" does not have deletion protection enabled`,
        'MEDIUM',
        { dbId, deletionProtection: instance.DeletionProtection },
        `Enable deletion protection for database instance "${dbId}"`,
        ['rds', 'data-protection', 'disaster-recovery']
      ));
    }

    // Check Multi-AZ
    if (!instance.MultiAZ) {
      findings.push(this.createFinding(
        'Multi-AZ Not Enabled',
        `Database instance "${dbId}" is not deployed across multiple availability zones`,
        'MEDIUM',
        { dbId, multiAz: instance.MultiAZ },
        `Enable Multi-AZ deployment for database instance "${dbId}" for high availability`,
        ['rds', 'high-availability', 'disaster-recovery']
      ));
    }

    // Check copy tags to snapshot
    if (!instance.CopyTagsToSnapshot) {
      findings.push(this.createFinding(
        'Copy Tags to Snapshot Not Enabled',
        `Database instance "${dbId}" does not copy tags to snapshots`,
        'LOW',
        { dbId },
        `Enable copy tags to snapshot for database instance "${dbId}"`,
        ['rds', 'backup', 'tagging']
      ));
    }

    return findings;
  }

  private async validateDBCluster(cluster: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const clusterId = cluster.DBClusterIdentifier || 'Unknown';

    // Check encryption
    if (!cluster.StorageEncrypted) {
      findings.push(this.createFinding(
        'RDS Cluster Not Encrypted',
        `Database cluster "${clusterId}" does not have storage encryption enabled`,
        'HIGH',
        { clusterId, storageEncrypted: cluster.StorageEncrypted },
        `Enable encryption at rest for database cluster "${clusterId}"`,
        ['rds', 'encryption', 'data-protection']
      ));
    }

    // Check backup retention
    if ((cluster.BackupRetentionPeriod || 0) < 7) {
      findings.push(this.createFinding(
        'Short Cluster Backup Retention',
        `Database cluster "${clusterId}" has only ${cluster.BackupRetentionPeriod}-day backup retention`,
        'MEDIUM',
        { clusterId, retentionDays: cluster.BackupRetentionPeriod },
        `Increase backup retention to at least 7 days for cluster "${clusterId}"`,
        ['rds', 'backup', 'disaster-recovery']
      ));
    }

    return findings;
  }
}

export default RDSScanner;
