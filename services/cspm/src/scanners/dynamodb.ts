import {
  ListTablesCommand,
  DescribeTableCommand,
  DescribeContinuousBackupsCommand,
  DescribeTableReplicaAutoScalingCommand,
} from '@aws-sdk/client-dynamodb';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class DynamoDBScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'DynamoDB');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting DynamoDB security scan...');

    const tableNames = await this.listAllTables();
    logger.info(`DynamoDB: scanning ${tableNames.length} table(s)`);

    for (const tableName of tableNames) {
      const tableFindings = await this.scanTable(tableName);
      findings.push(...tableFindings);
    }

    logger.info(`DynamoDB scan complete. ${findings.length} findings.`);
    return findings;
  }

  private async listAllTables(): Promise<string[]> {
    const names: string[] = [];
    let lastKey: string | undefined;
    try {
      do {
        const result = await retry(() =>
          this.client.dynamodb.send(new ListTablesCommand({ ExclusiveStartTableName: lastKey, Limit: 100 }))
        );
        names.push(...(result.TableNames ?? []));
        lastKey = result.LastEvaluatedTableName;
      } while (lastKey);
    } catch { /* no permission */ }
    return names;
  }

  private async scanTable(tableName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const [tableResult, backupResult] = await Promise.allSettled([
      retry(() => this.client.dynamodb.send(new DescribeTableCommand({ TableName: tableName }))),
      retry(() => this.client.dynamodb.send(new DescribeContinuousBackupsCommand({ TableName: tableName }))),
    ]);

    const table = tableResult.status === 'fulfilled' ? tableResult.value.Table : null;
    if (!table) return findings;

    const tableArn = table.TableArn ?? tableName;

    findings.push(...(await this.checkReplicaAutoScaling(tableName, tableArn, table)));

    // 1. Encryption — check if using AWS-managed key (default) vs CMK vs no encryption
    const sseType = table.SSEDescription?.SSEType;
    const sseStatus = table.SSEDescription?.Status;
    if (!sseStatus || sseStatus === 'DISABLED') {
      findings.push(this.emit(
        'dynamodb_tables_kms_cmk_encryption_enabled',
        { resourceId: tableArn, tableName, tableArn, sseType: sseType ?? 'NONE' },
        {
          message: `DynamoDB table "${tableName}" is not encrypted with a customer-managed KMS key. ` +
            `Data is either unencrypted or uses only AWS-owned keys which cannot be audited or rotated by you.`,
          remediation: `Enable CMK encryption: aws dynamodb update-table --table-name ${tableName} ` +
            `--sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=<your-key-arn>`,
        }
      ));
    }

    // 2. Point-in-time recovery (PITR)
    const backup = backupResult.status === 'fulfilled' ? backupResult.value : null;
    const pitrEnabled = backup?.ContinuousBackupsDescription?.PointInTimeRecoveryDescription?.PointInTimeRecoveryStatus === 'ENABLED';
    if (!pitrEnabled) {
      findings.push(this.emit(
        'dynamodb_tables_pitr_enabled',
        { resourceId: `${tableArn}::pitr`, tableName, tableArn },
        {
          message: `DynamoDB table "${tableName}" does not have Point-in-Time Recovery (PITR) enabled. ` +
            `Without PITR, accidental deletes or corruption cannot be recovered within a 35-day window.`,
          remediation: `Enable PITR: aws dynamodb update-continuous-backups --table-name ${tableName} ` +
            `--point-in-time-recovery-specification PointInTimeRecoveryEnabled=true`,
        }
      ));
    }

    // 3. No deletion protection
    if (!table.DeletionProtectionEnabled) {
      findings.push(this.emit(
        'dynamodb_table_deletion_protection_enabled',
        { resourceId: `${tableArn}::deletion-protection`, tableName, tableArn },
        {
          message: `DynamoDB table "${tableName}" does not have deletion protection enabled. ` +
            `The table can be deleted accidentally or by a compromised credential.`,
          remediation: `Enable deletion protection: aws dynamodb update-table --table-name ${tableName} --deletion-protection-enabled`,
        }
      ));
    }

    return findings;
  }

  private async checkReplicaAutoScaling(
    tableName: string,
    tableArn: string,
    table: any,
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    // Only matters for global tables (multi-region replicas)
    const replicas = table.Replicas ?? [];
    if (replicas.length === 0) return findings;

    let scaling: any;
    try {
      scaling = await retry(() =>
        this.client.dynamodb.send(new DescribeTableReplicaAutoScalingCommand({ TableName: tableName }))
      );
    } catch { return findings; }

    const replicaDescriptions = scaling?.TableAutoScalingDescription?.Replicas ?? [];
    const unscaled: string[] = [];
    for (const r of replicaDescriptions) {
      const region = r.RegionName ?? 'unknown';
      const gsis = r.ReplicaProvisionedReadCapacityAutoScalingSettings;
      const writeAutoScaling = r.ReplicaProvisionedWriteCapacityAutoScalingSettings;
      // Replica is missing autoscaling if both read and write settings are absent (PROVISIONED mode only)
      if (!gsis && !writeAutoScaling) {
        unscaled.push(region);
      }
    }

    if (unscaled.length > 0) {
      findings.push(this.emit(
        'dynamodb_table_replica_autoscaling_enabled',
        { resourceId: `${tableArn}::replica-autoscaling`, tableName, tableArn, regions: unscaled },
        {
          message: `DynamoDB global table "${tableName}" has ${unscaled.length} replica region(s) without autoscaling: ${unscaled.join(', ')}. ` +
            `Without autoscaling, replicas can be throttled under load or over-provisioned (cost).`,
        }
      ));
    }
    return findings;
  }
}

export default DynamoDBScanner;
