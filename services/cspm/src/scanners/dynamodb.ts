// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  ListTablesCommand,
  DescribeTableCommand,
  DescribeContinuousBackupsCommand,
  DescribeTableReplicaAutoScalingCommand,
  GetResourcePolicyCommand,
} from '@aws-sdk/client-dynamodb';
import { DAXClient, DescribeClustersCommand } from '@aws-sdk/client-dax';
import {
  ApplicationAutoScalingClient,
  DescribeScalableTargetsCommand,
} from '@aws-sdk/client-application-auto-scaling';
import {
  BackupClient,
  ListProtectedResourcesCommand,
  ListBackupPlansCommand,
  ListBackupSelectionsCommand,
  GetBackupSelectionCommand,
} from '@aws-sdk/client-backup';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Condition keys that scope a statement to a specific source/principal;
// Prowler's is_policy_public treats such statements as not cross-account exposed.
const RESTRICTIVE_CONDITION_KEYS = [
  'aws:sourcevpc',
  'aws:sourcevpce',
  'aws:sourceaccount',
  'aws:sourcearn',
  'aws:sourceowner',
  'aws:principalorgid',
  'aws:principalaccount',
  'aws:principalarn',
];

function hasRestrictiveCondition(statement: any): boolean {
  const condition = statement?.Condition;
  if (!condition || typeof condition !== 'object') return false;
  for (const operator of Object.keys(condition)) {
    const block = condition[operator];
    if (block && typeof block === 'object') {
      for (const key of Object.keys(block)) {
        if (RESTRICTIVE_CONDITION_KEYS.includes(key.toLowerCase())) return true;
      }
    }
  }
  return false;
}

/** Simplified port of Prowler's is_policy_public(is_cross_account_allowed=False): wildcard or foreign-account principals. */
function policyAllowsCrossAccount(policy: any, accountId: string): boolean {
  const rawStatements = policy?.Statement;
  const statements: any[] = Array.isArray(rawStatements) ? rawStatements : rawStatements ? [rawStatements] : [];
  for (const statement of statements) {
    if (statement?.Effect !== 'Allow') continue;
    if (hasRestrictiveCondition(statement)) continue;

    const principal = statement.Principal;
    let principals: string[] = [];
    if (typeof principal === 'string') principals = [principal];
    else if (principal && typeof principal === 'object') {
      const aws = principal.AWS;
      if (typeof aws === 'string') principals = [aws];
      else if (Array.isArray(aws)) principals = aws;
    }

    for (const entry of principals) {
      if (entry === '*') return true;
      const arnMatch = entry.match(/^arn:[^:]+:(?:iam|sts)::(\d{12}):/);
      const principalAccount = arnMatch ? arnMatch[1] : (/^\d{12}$/.test(entry) ? entry : null);
      if (principalAccount && principalAccount !== accountId) return true;
    }
  }
  return false;
}

export class DynamoDBScanner extends BaseScanner {
  private dax: DAXClient;
  private appAutoScaling: ApplicationAutoScalingClient;
  private backup: BackupClient;

  constructor(client: AWSClient) {
    super(client, 'DynamoDB');
    this.dax = new DAXClient(client.getClientConfig());
    this.appAutoScaling = new ApplicationAutoScalingClient(client.getClientConfig());
    this.backup = new BackupClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting DynamoDB security scan...');

    const tableNames = await this.listAllTables();
    logger.info(`DynamoDB: scanning ${tableNames.length} table(s)`);

    let accountId: string | null = null;
    try {
      accountId = await this.client.getAccountId();
    } catch (error) {
      logger.debug('Failed to resolve account id for DynamoDB cross-account check', { error: (error as Error).message });
    }

    const scalableDimensionsByTable = tableNames.length > 0
      ? await this.getDynamoDBScalableDimensions()
      : new Map<string, Set<string>>();
    const protectedResources = tableNames.length > 0 ? await this.getBackupProtectedResources() : null;

    for (const tableName of tableNames) {
      const tableFindings = await this.scanTable(tableName, accountId, scalableDimensionsByTable, protectedResources);
      findings.push(...tableFindings);
    }

    findings.push(...(await this.scanDaxClusters()));

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

  private async scanTable(
    tableName: string,
    accountId: string | null,
    scalableDimensionsByTable: Map<string, Set<string>>,
    protectedResources: Set<string> | null,
  ): Promise<ScanningResult[]> {
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

    // 4. dynamodb_table_autoscaling_enabled: PROVISIONED tables need auto scaling for reads and writes
    const billingMode = table.BillingModeSummary?.BillingMode ?? 'PROVISIONED';
    if (billingMode === 'PROVISIONED') {
      const dimensions = scalableDimensionsByTable.get(tableName) ?? new Set<string>();
      const missingAutoscaling: string[] = [];
      if (!dimensions.has('dynamodb:table:ReadCapacityUnits')) missingAutoscaling.push('read');
      if (!dimensions.has('dynamodb:table:WriteCapacityUnits')) missingAutoscaling.push('write');
      if (missingAutoscaling.length > 0) {
        findings.push(this.emit(
          'dynamodb_table_autoscaling_enabled',
          { resourceId: `${tableArn}::autoscaling`, tableName, tableArn, billingMode, missingAutoscaling },
          {
            message: `DynamoDB table "${tableName}" is in provisioned mode without auto scaling enabled for ${missingAutoscaling.join(' and ')} capacity. ` +
              `Traffic spikes throttle requests instead of scaling capacity.`,
            remediation: `Switch to on-demand capacity: aws dynamodb update-table --table-name ${tableName} --billing-mode PAY_PER_REQUEST, ` +
              `or register Application Auto Scaling targets for both read and write capacity units.`,
          }
        ));
      }
    }

    // 5. dynamodb_table_cross_account_access
    if (accountId) {
      findings.push(...(await this.checkCrossAccountAccess(tableName, tableArn, accountId)));
    }

    // 6. dynamodb_table_protected_by_backup_plan
    if (protectedResources) {
      const partition = tableArn.split(':')[1] || 'aws';
      const covered =
        protectedResources.has(tableArn) ||
        protectedResources.has(`arn:${partition}:dynamodb:*:*:table/*`) ||
        protectedResources.has('*');
      if (!covered) {
        findings.push(this.emit(
          'dynamodb_table_protected_by_backup_plan',
          { resourceId: `${tableArn}::backup-plan`, tableName, tableArn },
          {
            message: `DynamoDB table "${tableName}" is not protected by an AWS Backup plan. ` +
              `Without governed backups, accidental deletes or corrupt writes may be unrecoverable and RPO/RTO targets cannot be met.`,
            remediation: `Assign table "${tableName}" (directly, by tag, or via a resource-type wildcard) to an AWS Backup plan with an appropriate schedule and retention.`,
          }
        ));
      }
    }

    return findings;
  }

  private async checkCrossAccountAccess(
    tableName: string,
    tableArn: string,
    accountId: string,
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    let policy: any = null;
    try {
      const result: any = await retry(() =>
        this.client.dynamodb.send(new GetResourcePolicyCommand({ ResourceArn: tableArn }))
      );
      policy = result.Policy ? JSON.parse(result.Policy) : null;
    } catch (error) {
      // PolicyNotFoundException / ResourceNotFoundException => table has no resource policy
      logger.debug(`No resource policy for DynamoDB table ${tableName}`, { error: (error as Error).message });
      return findings;
    }
    if (!policy) return findings;

    if (policyAllowsCrossAccount(policy, accountId)) {
      findings.push(this.emit(
        'dynamodb_table_cross_account_access',
        { resourceId: `${tableArn}::cross-account`, tableName, tableArn, policy },
        {
          message: `DynamoDB table "${tableName}" has a resource-based policy allowing cross-account access. ` +
            `External principals can read or write data and consume the table's capacity.`,
          remediation: `Scope the resource policy of "${tableName}" to same-account principals or delete it: ` +
            `aws dynamodb delete-resource-policy --resource-arn ${tableArn}`,
        }
      ));
    }
    return findings;
  }

  /** table name -> registered Application Auto Scaling dimensions (e.g. dynamodb:table:ReadCapacityUnits). */
  private async getDynamoDBScalableDimensions(): Promise<Map<string, Set<string>>> {
    const mapping = new Map<string, Set<string>>();
    try {
      let nextToken: string | undefined;
      do {
        const result: any = await retry(() =>
          this.appAutoScaling.send(new DescribeScalableTargetsCommand({ ServiceNamespace: 'dynamodb', NextToken: nextToken }))
        );
        for (const target of result.ScalableTargets ?? []) {
          const resourceId: string = target.ResourceId ?? '';
          if (!resourceId.startsWith('table/')) continue;
          const tableName = resourceId.split('/')[1];
          if (!mapping.has(tableName)) mapping.set(tableName, new Set());
          mapping.get(tableName)!.add(target.ScalableDimension ?? '');
        }
        nextToken = result.NextToken;
      } while (nextToken);
    } catch (error) {
      logger.debug('Failed to describe Application Auto Scaling targets for DynamoDB', { error: (error as Error).message });
    }
    return mapping;
  }

  /** ARNs (and backup selection patterns) covered by AWS Backup; null when the Backup API is unavailable. */
  private async getBackupProtectedResources(): Promise<Set<string> | null> {
    const protectedResources = new Set<string>();
    try {
      let nextToken: string | undefined;
      do {
        const result: any = await retry(() =>
          this.backup.send(new ListProtectedResourcesCommand({ NextToken: nextToken }))
        );
        for (const resource of result.Results ?? []) {
          if (resource.ResourceArn) protectedResources.add(resource.ResourceArn);
        }
        nextToken = result.NextToken;
      } while (nextToken);
    } catch (error) {
      logger.debug('Failed to list AWS Backup protected resources', { error: (error as Error).message });
      return null;
    }

    // Best-effort: include backup plan selection patterns (e.g. arn:aws:dynamodb:*:*:table/*)
    try {
      const planIds: string[] = [];
      let plansToken: string | undefined;
      do {
        const result: any = await retry(() =>
          this.backup.send(new ListBackupPlansCommand({ NextToken: plansToken }))
        );
        for (const plan of result.BackupPlansList ?? []) {
          if (plan.BackupPlanId) planIds.push(plan.BackupPlanId);
        }
        plansToken = result.NextToken;
      } while (plansToken);

      for (const planId of planIds) {
        let selectionsToken: string | undefined;
        do {
          const selections: any = await retry(() =>
            this.backup.send(new ListBackupSelectionsCommand({ BackupPlanId: planId, NextToken: selectionsToken }))
          );
          for (const selection of selections.BackupSelectionsList ?? []) {
            if (!selection.SelectionId) continue;
            const detail: any = await retry(() =>
              this.backup.send(new GetBackupSelectionCommand({ BackupPlanId: planId, SelectionId: selection.SelectionId }))
            );
            for (const resourceArn of detail.BackupSelection?.Resources ?? []) {
              protectedResources.add(resourceArn);
            }
          }
          selectionsToken = selections.NextToken;
        } while (selectionsToken);
      }
    } catch (error) {
      logger.debug('Failed to list AWS Backup plan selections', { error: (error as Error).message });
    }

    return protectedResources;
  }

  // dynamodb_accelerator_cluster_{encryption_enabled,in_transit_encryption_enabled,multi_az}
  private async scanDaxClusters(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const clusters: any[] = [];
    try {
      let nextToken: string | undefined;
      do {
        const result: any = await retry(() =>
          this.dax.send(new DescribeClustersCommand({ NextToken: nextToken }))
        );
        clusters.push(...(result.Clusters ?? []));
        nextToken = result.NextToken;
      } while (nextToken);
    } catch (error) {
      logger.debug('Failed to describe DAX clusters', { error: (error as Error).message });
      return findings;
    }
    logger.info(`DynamoDB: scanning ${clusters.length} DAX cluster(s)`);

    for (const cluster of clusters) {
      const clusterName: string = cluster.ClusterName ?? 'Unknown';
      const clusterArn: string = cluster.ClusterArn ?? clusterName;

      // dynamodb_accelerator_cluster_encryption_enabled
      if (cluster.SSEDescription?.Status !== 'ENABLED') {
        findings.push(this.emit(
          'dynamodb_accelerator_cluster_encryption_enabled',
          { resourceId: clusterArn, clusterName, clusterArn, sseStatus: cluster.SSEDescription?.Status ?? 'DISABLED' },
          {
            message: `DAX cluster "${clusterName}" does not have encryption at rest enabled. ` +
              `On-disk cache, configuration and logs can be read from the underlying storage.`,
            remediation: `Recreate the cluster with --sse-specification Enabled=true (encryption cannot be enabled in place), ` +
              `point the application at the new endpoint, then delete "${clusterName}".`,
          }
        ));
      }

      // dynamodb_accelerator_cluster_in_transit_encryption_enabled
      if (cluster.ClusterEndpointEncryptionType !== 'TLS') {
        findings.push(this.emit(
          'dynamodb_accelerator_cluster_in_transit_encryption_enabled',
          { resourceId: `${clusterArn}::tls`, clusterName, clusterArn, clusterEndpointEncryptionType: cluster.ClusterEndpointEncryptionType ?? 'NONE' },
          {
            message: `DAX cluster "${clusterName}" does not have encryption in transit enabled. ` +
              `Client traffic to the cluster can be intercepted or tampered with.`,
            remediation: `Create a new cluster with --cluster-endpoint-encryption-type TLS, migrate the application, ` +
              `then delete "${clusterName}" (endpoint encryption cannot be changed in place).`,
          }
        ));
      }

      // dynamodb_accelerator_cluster_multi_az
      const nodeAzs: string[] = (cluster.Nodes ?? [])
        .map((node: any) => node.AvailabilityZone)
        .filter((az: any) => !!az);
      if (nodeAzs.length <= 1) {
        findings.push(this.emit(
          'dynamodb_accelerator_cluster_multi_az',
          { resourceId: `${clusterArn}::multi-az`, clusterName, clusterArn, nodeAzs },
          {
            message: `DAX cluster "${clusterName}" does not have nodes in multiple availability zones. ` +
              `An AZ outage or node failure makes the cache unavailable and shifts full load onto DynamoDB.`,
            remediation: `Add nodes across AZs: aws dax increase-replication-factor --cluster-name ${clusterName} ` +
              `--new-replication-factor 2 --availability-zones <az-1> <az-2>`,
          }
        ));
      }
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
