import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  DynamoDBClient,
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
} from '@aws-sdk/client-backup';
import DynamoDBScanner from '../../../src/scanners/dynamodb';
import AWSClient from '../../../src/aws/client';

const dynamodbMock = mockClient(DynamoDBClient);
const daxMock = mockClient(DAXClient);
const appAutoScalingMock = mockClient(ApplicationAutoScalingClient);
const backupMock = mockClient(BackupClient);

/**
 * DynamoDBScanner's constructor builds its own DAX / ApplicationAutoScaling /
 * Backup SDK clients from client.getClientConfig(), but talks to DynamoDB
 * itself, and to getAccountId(), directly via `this.client.dynamodb` /
 * `this.client.getAccountId()` — mirrors the lambda.test.ts pattern.
 */
function makeMockClient(accountId: string | null = '123456789012'): AWSClient {
  return {
    dynamodb: new DynamoDBClient({ region: 'us-east-1', credentials: {} as any }),
    getAccountId: async () => {
      if (!accountId) throw new Error('no account id');
      return accountId;
    },
    getClientConfig: () => ({ region: 'us-east-1', credentials: {} }),
  } as unknown as AWSClient;
}

// Default "nothing configured" responses so every table/cluster resolves
// cleanly unless a test overrides it.
function resetToEmptyDefaults() {
  dynamodbMock.reset();
  daxMock.reset();
  appAutoScalingMock.reset();
  backupMock.reset();

  dynamodbMock.on(ListTablesCommand).resolves({ TableNames: [] });
  dynamodbMock.on(DescribeContinuousBackupsCommand).resolves({
    ContinuousBackupsDescription: {
      PointInTimeRecoveryDescription: { PointInTimeRecoveryStatus: 'ENABLED' },
    },
  });
  dynamodbMock.on(DescribeTableReplicaAutoScalingCommand).resolves({
    TableAutoScalingDescription: { Replicas: [] },
  });
  dynamodbMock.on(GetResourcePolicyCommand).rejects(
    Object.assign(new Error('no resource policy'), { name: 'PolicyNotFoundException' })
  );

  daxMock.on(DescribeClustersCommand).resolves({ Clusters: [] });
  appAutoScalingMock.on(DescribeScalableTargetsCommand).resolves({ ScalableTargets: [] });
  backupMock.on(ListProtectedResourcesCommand).resolves({ Results: [] });
  backupMock.on(ListBackupPlansCommand).resolves({ BackupPlansList: [] });
}

// A "safe" baseline table that should NOT trigger any of the checks asserted
// in this file, so tests can override just the field(s) under test.
function safeTable(overrides: Record<string, any> = {}) {
  return {
    TableName: 'table-safe',
    TableArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/table-safe',
    SSEDescription: { SSEType: 'KMS', Status: 'ENABLED' },
    DeletionProtectionEnabled: true,
    BillingModeSummary: { BillingMode: 'PAY_PER_REQUEST' },
    Replicas: [],
    ...overrides,
  };
}

describe('DynamoDBScanner', () => {
  beforeEach(() => {
    resetToEmptyDefaults();
  });

  afterEach(() => {
    dynamodbMock.reset();
    daxMock.reset();
    appAutoScalingMock.reset();
    backupMock.reset();
  });

  describe('scan() — happy path with findings', () => {
    it('flags an unencrypted table without PITR, deletion protection, or backup-plan coverage', async () => {
      dynamodbMock.on(ListTablesCommand).resolves({ TableNames: ['table-risky'] });
      dynamodbMock.on(DescribeTableCommand).resolves({
        Table: safeTable({
          TableName: 'table-risky',
          TableArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/table-risky',
          SSEDescription: { SSEType: undefined, Status: 'DISABLED' },
          DeletionProtectionEnabled: false,
        }),
      });
      dynamodbMock.on(DescribeContinuousBackupsCommand).resolves({
        ContinuousBackupsDescription: {
          PointInTimeRecoveryDescription: { PointInTimeRecoveryStatus: 'DISABLED' },
        },
      });

      const scanner = new DynamoDBScanner(makeMockClient());
      const findings = await scanner.scan();

      const encryptionFinding = findings.find((f) => f.checkId === 'dynamodb_tables_kms_cmk_encryption_enabled');
      expect(encryptionFinding).toBeDefined();
      expect(encryptionFinding?.service).toBe('DynamoDB');
      expect(encryptionFinding?.evidence).toMatchObject({ tableName: 'table-risky', sseType: 'NONE' });

      const pitrFinding = findings.find((f) => f.checkId === 'dynamodb_tables_pitr_enabled');
      expect(pitrFinding).toBeDefined();
      expect(pitrFinding?.evidence).toMatchObject({ tableName: 'table-risky' });

      const deletionProtectionFinding = findings.find((f) => f.checkId === 'dynamodb_table_deletion_protection_enabled');
      expect(deletionProtectionFinding).toBeDefined();

      const backupPlanFinding = findings.find((f) => f.checkId === 'dynamodb_table_protected_by_backup_plan');
      expect(backupPlanFinding).toBeDefined();
      expect(backupPlanFinding?.evidence).toMatchObject({ tableName: 'table-risky' });
    });

    it('does not flag a fully-compliant table for the baseline checks', async () => {
      dynamodbMock.on(ListTablesCommand).resolves({ TableNames: ['table-safe'] });
      dynamodbMock.on(DescribeTableCommand).resolves({ Table: safeTable() });
      backupMock.on(ListProtectedResourcesCommand).resolves({
        Results: [{ ResourceArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/table-safe' }],
      });

      const scanner = new DynamoDBScanner(makeMockClient());
      const findings = await scanner.scan();

      const baselineCheckIds = [
        'dynamodb_tables_kms_cmk_encryption_enabled',
        'dynamodb_tables_pitr_enabled',
        'dynamodb_table_deletion_protection_enabled',
        'dynamodb_table_autoscaling_enabled',
        'dynamodb_table_protected_by_backup_plan',
        'dynamodb_table_cross_account_access',
      ];
      const unexpected = findings.filter((f) => baselineCheckIds.includes(f.checkId ?? ''));
      expect(unexpected).toEqual([]);
    });

    it('flags a provisioned table missing autoscaling for both read and write capacity', async () => {
      dynamodbMock.on(ListTablesCommand).resolves({ TableNames: ['table-provisioned'] });
      dynamodbMock.on(DescribeTableCommand).resolves({
        Table: safeTable({
          TableName: 'table-provisioned',
          TableArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/table-provisioned',
          BillingModeSummary: { BillingMode: 'PROVISIONED' },
        }),
      });
      appAutoScalingMock.on(DescribeScalableTargetsCommand).resolves({ ScalableTargets: [] });

      const scanner = new DynamoDBScanner(makeMockClient());
      const findings = await scanner.scan();

      const autoscalingFinding = findings.find((f) => f.checkId === 'dynamodb_table_autoscaling_enabled');
      expect(autoscalingFinding).toBeDefined();
      expect(autoscalingFinding?.evidence).toMatchObject({
        tableName: 'table-provisioned',
        missingAutoscaling: ['read', 'write'],
      });
    });

    it('does not flag autoscaling when both read and write scalable targets are registered', async () => {
      dynamodbMock.on(ListTablesCommand).resolves({ TableNames: ['table-scaled'] });
      dynamodbMock.on(DescribeTableCommand).resolves({
        Table: safeTable({
          TableName: 'table-scaled',
          TableArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/table-scaled',
          BillingModeSummary: { BillingMode: 'PROVISIONED' },
        }),
      });
      appAutoScalingMock.on(DescribeScalableTargetsCommand).resolves({
        ScalableTargets: [
          { ResourceId: 'table/table-scaled', ScalableDimension: 'dynamodb:table:ReadCapacityUnits' },
          { ResourceId: 'table/table-scaled', ScalableDimension: 'dynamodb:table:WriteCapacityUnits' },
        ],
      });

      const scanner = new DynamoDBScanner(makeMockClient());
      const findings = await scanner.scan();

      const autoscalingFinding = findings.find((f) => f.checkId === 'dynamodb_table_autoscaling_enabled');
      expect(autoscalingFinding).toBeUndefined();
    });

    it('flags a table with a resource policy allowing cross-account access', async () => {
      const tableArn = 'arn:aws:dynamodb:us-east-1:123456789012:table/table-shared';
      dynamodbMock.on(ListTablesCommand).resolves({ TableNames: ['table-shared'] });
      dynamodbMock.on(DescribeTableCommand).resolves({
        Table: safeTable({ TableName: 'table-shared', TableArn: tableArn }),
      });
      dynamodbMock.on(GetResourcePolicyCommand).resolves({
        Policy: JSON.stringify({
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: '999999999999' },
              Action: 'dynamodb:GetItem',
              Resource: tableArn,
            },
          ],
        }),
      });

      const scanner = new DynamoDBScanner(makeMockClient('123456789012'));
      const findings = await scanner.scan();

      const crossAccountFinding = findings.find((f) => f.checkId === 'dynamodb_table_cross_account_access');
      expect(crossAccountFinding).toBeDefined();
      expect(crossAccountFinding?.evidence).toMatchObject({ tableName: 'table-shared', tableArn });
    });

    it('does not flag cross-account access when the resource policy is scoped to the same account', async () => {
      const tableArn = 'arn:aws:dynamodb:us-east-1:123456789012:table/table-scoped';
      dynamodbMock.on(ListTablesCommand).resolves({ TableNames: ['table-scoped'] });
      dynamodbMock.on(DescribeTableCommand).resolves({
        Table: safeTable({ TableName: 'table-scoped', TableArn: tableArn }),
      });
      dynamodbMock.on(GetResourcePolicyCommand).resolves({
        Policy: JSON.stringify({
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: '123456789012' },
              Action: 'dynamodb:GetItem',
              Resource: tableArn,
            },
          ],
        }),
      });

      const scanner = new DynamoDBScanner(makeMockClient('123456789012'));
      const findings = await scanner.scan();

      const crossAccountFinding = findings.find((f) => f.checkId === 'dynamodb_table_cross_account_access');
      expect(crossAccountFinding).toBeUndefined();
    });

    it('flags a DAX cluster without encryption at rest, in-transit TLS, or multi-AZ nodes', async () => {
      daxMock.on(DescribeClustersCommand).resolves({
        Clusters: [
          {
            ClusterName: 'dax-risky',
            ClusterArn: 'arn:aws:dax:us-east-1:123456789012:cache/dax-risky',
            SSEDescription: { Status: 'DISABLED' },
            ClusterEndpointEncryptionType: 'NONE',
            Nodes: [{ AvailabilityZone: 'us-east-1a' }],
          },
        ],
      });

      const scanner = new DynamoDBScanner(makeMockClient());
      const findings = await scanner.scan();

      const encryptionFinding = findings.find((f) => f.checkId === 'dynamodb_accelerator_cluster_encryption_enabled');
      expect(encryptionFinding).toBeDefined();
      expect(encryptionFinding?.service).toBe('DynamoDB');
      expect(encryptionFinding?.evidence).toMatchObject({ clusterName: 'dax-risky', sseStatus: 'DISABLED' });

      const transitFinding = findings.find((f) => f.checkId === 'dynamodb_accelerator_cluster_in_transit_encryption_enabled');
      expect(transitFinding).toBeDefined();

      const multiAzFinding = findings.find((f) => f.checkId === 'dynamodb_accelerator_cluster_multi_az');
      expect(multiAzFinding).toBeDefined();
      expect(multiAzFinding?.evidence).toMatchObject({ clusterName: 'dax-risky', nodeAzs: ['us-east-1a'] });
    });

    it('does not flag a DAX cluster that is encrypted, TLS-enabled, and multi-AZ', async () => {
      daxMock.on(DescribeClustersCommand).resolves({
        Clusters: [
          {
            ClusterName: 'dax-safe',
            ClusterArn: 'arn:aws:dax:us-east-1:123456789012:cache/dax-safe',
            SSEDescription: { Status: 'ENABLED' },
            ClusterEndpointEncryptionType: 'TLS',
            Nodes: [{ AvailabilityZone: 'us-east-1a' }, { AvailabilityZone: 'us-east-1b' }],
          },
        ],
      });

      const scanner = new DynamoDBScanner(makeMockClient());
      const findings = await scanner.scan();

      const daxCheckIds = [
        'dynamodb_accelerator_cluster_encryption_enabled',
        'dynamodb_accelerator_cluster_in_transit_encryption_enabled',
        'dynamodb_accelerator_cluster_multi_az',
      ];
      const unexpected = findings.filter((f) => daxCheckIds.includes(f.checkId ?? ''));
      expect(unexpected).toEqual([]);
    });

    it('flags a global table replica missing autoscaling', async () => {
      const tableArn = 'arn:aws:dynamodb:us-east-1:123456789012:table/table-global';
      dynamodbMock.on(ListTablesCommand).resolves({ TableNames: ['table-global'] });
      dynamodbMock.on(DescribeTableCommand).resolves({
        Table: safeTable({
          TableName: 'table-global',
          TableArn: tableArn,
          Replicas: [{ RegionName: 'eu-west-1' }],
        }),
      });
      dynamodbMock.on(DescribeTableReplicaAutoScalingCommand).resolves({
        TableAutoScalingDescription: {
          Replicas: [{ RegionName: 'eu-west-1' }],
        },
      });

      const scanner = new DynamoDBScanner(makeMockClient());
      const findings = await scanner.scan();

      const replicaFinding = findings.find((f) => f.checkId === 'dynamodb_table_replica_autoscaling_enabled');
      expect(replicaFinding).toBeDefined();
      expect(replicaFinding?.evidence).toMatchObject({ tableName: 'table-global', regions: ['eu-west-1'] });
    });
  });

  describe('scan() — no resources', () => {
    it('returns an empty finding list when there are no tables or DAX clusters', async () => {
      const scanner = new DynamoDBScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });
  });

  describe('scan() — pagination', () => {
    it('follows the ExclusiveStartTableName pagination loop across two pages of ListTables', async () => {
      dynamodbMock
        .on(ListTablesCommand)
        .resolvesOnce({ TableNames: ['table-page-1'], LastEvaluatedTableName: 'table-page-1' })
        .resolvesOnce({ TableNames: ['table-page-2'] });

      dynamodbMock.on(DescribeTableCommand).callsFake((input: any) =>
        Promise.resolve({
          Table: safeTable({
            TableName: input.TableName,
            TableArn: `arn:aws:dynamodb:us-east-1:123456789012:table/${input.TableName}`,
            SSEDescription: { SSEType: undefined, Status: 'DISABLED' },
          }),
        })
      );

      const scanner = new DynamoDBScanner(makeMockClient());
      const findings = await scanner.scan();

      const encryptionFindings = findings.filter((f) => f.checkId === 'dynamodb_tables_kms_cmk_encryption_enabled');
      const tableNames = encryptionFindings.map((f) => (f.evidence as any).tableName).sort();
      expect(tableNames).toEqual(['table-page-1', 'table-page-2']);
      expect(dynamodbMock.commandCalls(ListTablesCommand)).toHaveLength(2);
    });

    it('follows the NextToken pagination loop across two pages of DescribeScalableTargets', async () => {
      dynamodbMock.on(ListTablesCommand).resolves({ TableNames: ['table-a'] });
      dynamodbMock.on(DescribeTableCommand).resolves({
        Table: safeTable({
          TableName: 'table-a',
          TableArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/table-a',
          BillingModeSummary: { BillingMode: 'PROVISIONED' },
        }),
      });
      appAutoScalingMock
        .on(DescribeScalableTargetsCommand)
        .resolvesOnce({
          ScalableTargets: [{ ResourceId: 'table/table-a', ScalableDimension: 'dynamodb:table:ReadCapacityUnits' }],
          NextToken: 'page-2',
        })
        .resolvesOnce({
          ScalableTargets: [{ ResourceId: 'table/table-a', ScalableDimension: 'dynamodb:table:WriteCapacityUnits' }],
        });

      const scanner = new DynamoDBScanner(makeMockClient());
      const findings = await scanner.scan();

      const autoscalingFinding = findings.find((f) => f.checkId === 'dynamodb_table_autoscaling_enabled');
      expect(autoscalingFinding).toBeUndefined();
      expect(appAutoScalingMock.commandCalls(DescribeScalableTargetsCommand)).toHaveLength(2);
    });
  });

  describe('scan() — error handling', () => {
    it('does not throw and returns an empty array when ListTables rejects on every retry', async () => {
      dynamodbMock.on(ListTablesCommand).rejects(new Error('AccessDenied: dynamodb:ListTables'));

      const scanner = new DynamoDBScanner(makeMockClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    }, 20000);

    it('skips a table (no throw) when DescribeTable rejects but still scans other tables', async () => {
      dynamodbMock.on(ListTablesCommand).resolves({ TableNames: ['table-error', 'table-ok'] });
      dynamodbMock.on(DescribeTableCommand).callsFake((input: any) => {
        if (input.TableName === 'table-error') {
          return Promise.reject(new Error('ResourceNotFoundException'));
        }
        return Promise.resolve({
          Table: safeTable({
            TableName: 'table-ok',
            TableArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/table-ok',
            SSEDescription: { SSEType: undefined, Status: 'DISABLED' },
          }),
        });
      });

      const scanner = new DynamoDBScanner(makeMockClient());
      const findings = await scanner.scan();

      const encryptionFindings = findings.filter((f) => f.checkId === 'dynamodb_tables_kms_cmk_encryption_enabled');
      expect(encryptionFindings).toHaveLength(1);
      expect(encryptionFindings[0]?.evidence).toMatchObject({ tableName: 'table-ok' });
    }, 20000);

    it('does not flag cross-account access (no throw) when GetResourcePolicy rejects', async () => {
      dynamodbMock.on(ListTablesCommand).resolves({ TableNames: ['table-no-policy'] });
      dynamodbMock.on(DescribeTableCommand).resolves({
        Table: safeTable({
          TableName: 'table-no-policy',
          TableArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/table-no-policy',
        }),
      });
      dynamodbMock.on(GetResourcePolicyCommand).rejects(
        Object.assign(new Error('no resource policy'), { name: 'PolicyNotFoundException' })
      );

      const scanner = new DynamoDBScanner(makeMockClient());
      const findings = await scanner.scan();

      const crossAccountFinding = findings.find((f) => f.checkId === 'dynamodb_table_cross_account_access');
      expect(crossAccountFinding).toBeUndefined();
    });

    it('does not flag DAX findings (no throw) when DescribeClusters rejects on every retry', async () => {
      daxMock.on(DescribeClustersCommand).rejects(new Error('AccessDenied: dax:DescribeClusters'));

      const scanner = new DynamoDBScanner(makeMockClient());
      const findings = await scanner.scan();

      const daxCheckIds = [
        'dynamodb_accelerator_cluster_encryption_enabled',
        'dynamodb_accelerator_cluster_in_transit_encryption_enabled',
        'dynamodb_accelerator_cluster_multi_az',
      ];
      const unexpected = findings.filter((f) => daxCheckIds.includes(f.checkId ?? ''));
      expect(unexpected).toEqual([]);
    }, 20000);

    it('does not flag backup-plan protection (no throw) when AWS Backup ListProtectedResources rejects', async () => {
      dynamodbMock.on(ListTablesCommand).resolves({ TableNames: ['table-safe'] });
      dynamodbMock.on(DescribeTableCommand).resolves({ Table: safeTable() });
      backupMock.on(ListProtectedResourcesCommand).rejects(new Error('AccessDenied: backup:ListProtectedResources'));

      const scanner = new DynamoDBScanner(makeMockClient());
      const findings = await scanner.scan();

      const backupFinding = findings.find((f) => f.checkId === 'dynamodb_table_protected_by_backup_plan');
      expect(backupFinding).toBeUndefined();
    }, 20000);

    it('does not throw when getAccountId() fails, and skips the cross-account check', async () => {
      dynamodbMock.on(ListTablesCommand).resolves({ TableNames: ['table-no-account'] });
      dynamodbMock.on(DescribeTableCommand).resolves({
        Table: safeTable({
          TableName: 'table-no-account',
          TableArn: 'arn:aws:dynamodb:us-east-1:123456789012:table/table-no-account',
        }),
      });

      const scanner = new DynamoDBScanner(makeMockClient(null));
      const findings = await scanner.scan();

      const crossAccountFinding = findings.find((f) => f.checkId === 'dynamodb_table_cross_account_access');
      expect(crossAccountFinding).toBeUndefined();
      expect(dynamodbMock.commandCalls(GetResourcePolicyCommand)).toHaveLength(0);
    });
  });
});
