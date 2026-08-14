import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  RDSClient,
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
import RDSScanner from '../../../src/scanners/rds';

// Minimal stand-in for AWSClient. RDSScanner's constructor only ever touches
// `client.getClientConfig()` (to build the RDS + Backup SDK v3 clients) and
// `client.rds` (a pre-built RDSClient instance) at call time, per baseScanner's
// documented contract — mirrors the pattern used in scannersContract.test.ts.
function makeMockAWSClient(rds: RDSClient) {
  return {
    getClientConfig: () => ({ region: 'us-east-1', credentials: {} }),
    rds,
  } as any;
}

const rdsMock = mockClient(RDSClient);
const backupMock = mockClient(BackupClient);

// Empty-by-default responses for every describe/list call the scanner makes
// beyond DescribeDBInstances/DescribeDBClusters, so each test only needs to
// override the handlers relevant to what it's exercising.
function resetToEmptyDefaults() {
  rdsMock.reset();
  backupMock.reset();

  rdsMock.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });
  rdsMock.on(DescribeDBClustersCommand).resolves({ DBClusters: [] });
  rdsMock.on(DescribeDBSnapshotsCommand).resolves({ DBSnapshots: [] });
  rdsMock.on(DescribeDBClusterSnapshotsCommand).resolves({ DBClusterSnapshots: [] });
  rdsMock.on(DescribeDBSnapshotAttributesCommand).resolves({
    DBSnapshotAttributesResult: { DBSnapshotAttributes: [] },
  });
  rdsMock.on(DescribeDBClusterSnapshotAttributesCommand).resolves({
    DBClusterSnapshotAttributesResult: { DBClusterSnapshotAttributes: [] },
  });
  rdsMock.on(DescribeEventSubscriptionsCommand).resolves({ EventSubscriptionsList: [] });
  rdsMock.on(DescribeCertificatesCommand).resolves({ Certificates: [] });
  rdsMock.on(DescribeDBEngineVersionsCommand).resolves({ DBEngineVersions: [] });
  rdsMock.on(DescribeDBParametersCommand).resolves({ Parameters: [] });
  rdsMock.on(DescribeDBClusterParametersCommand).resolves({ Parameters: [] });

  backupMock.on(ListProtectedResourcesCommand).resolves({ Results: [] });
}

// A "safe" baseline DB instance that should NOT trigger any of the checks
// asserted in this file, so tests can override just the field(s) under test
// without wading through every other finding rds_instance_* would otherwise emit.
function safeInstance(overrides: Record<string, any> = {}) {
  return {
    DBInstanceIdentifier: 'db-safe',
    DBInstanceArn: 'arn:aws:rds:us-east-1:123456789012:db:db-safe',
    Engine: 'postgres',
    EngineVersion: '15.4',
    StorageEncrypted: true,
    BackupRetentionPeriod: 7,
    PubliclyAccessible: false,
    DeletionProtection: true,
    MultiAZ: true,
    CopyTagsToSnapshot: true,
    EnhancedMonitoringResourceArn: 'arn:aws:rds:us-east-1:123456789012:em-role',
    AutoMinorVersionUpgrade: true,
    EnabledCloudwatchLogsExports: ['postgresql'],
    DBSubnetGroup: { VpcId: 'vpc-123' },
    EngineLifecycleSupport: 'open-source-rds-standard-support',
    MasterUsername: 'app_admin',
    IAMDatabaseAuthenticationEnabled: true,
    Endpoint: { Port: 6543 },
    CACertificateIdentifier: undefined,
    ...overrides,
  };
}

function safeCluster(overrides: Record<string, any> = {}) {
  return {
    DBClusterIdentifier: 'cluster-safe',
    DBClusterArn: 'arn:aws:rds:us-east-1:123456789012:cluster:cluster-safe',
    Engine: 'aurora-postgresql',
    StorageEncrypted: true,
    BackupRetentionPeriod: 7,
    CopyTagsToSnapshot: true,
    MasterUsername: 'app_admin',
    DeletionProtection: true,
    IAMDatabaseAuthenticationEnabled: true,
    EnabledCloudwatchLogsExports: ['postgresql'],
    MultiAZ: false, // MultiAZ false suppresses rds_cluster_minor_version_upgrade_enabled (only checked when MultiAZ)
    Port: 6543,
    BacktrackWindow: 0,
    ...overrides,
  };
}

describe('RDSScanner', () => {
  beforeEach(() => {
    resetToEmptyDefaults();
  });

  afterEach(() => {
    rdsMock.reset();
    backupMock.reset();
  });

  describe('scan() — happy path with findings', () => {
    it('flags an unencrypted, publicly accessible instance with short backup retention', async () => {
      rdsMock.on(DescribeDBInstancesCommand).resolves({
        DBInstances: [
          safeInstance({
            DBInstanceIdentifier: 'db-risky',
            StorageEncrypted: false,
            PubliclyAccessible: true,
            BackupRetentionPeriod: 1,
          }),
        ],
      });

      const scanner = new RDSScanner(makeMockAWSClient(new RDSClient({})));
      const findings = await scanner.scan();

      const encryptionFinding = findings.find((f) => f.checkId === 'rds_instance_storage_encrypted');
      expect(encryptionFinding).toBeDefined();
      expect(encryptionFinding?.service).toBe('RDS');
      expect(encryptionFinding?.evidence).toMatchObject({ dbId: 'db-risky', storageEncrypted: false });

      const publicFinding = findings.find((f) => f.checkId === 'rds_instance_no_public_access');
      expect(publicFinding).toBeDefined();
      expect(publicFinding?.evidence).toMatchObject({ dbId: 'db-risky', publiclyAccessible: true });

      const backupFinding = findings.find((f) => f.checkId === 'rds_instance_backup_enabled');
      expect(backupFinding).toBeDefined();
      expect(backupFinding?.evidence).toMatchObject({ dbId: 'db-risky', retentionDays: 1 });
    });

    it('does not flag a fully-compliant instance for the baseline checks', async () => {
      rdsMock.on(DescribeDBInstancesCommand).resolves({ DBInstances: [safeInstance()] });

      const scanner = new RDSScanner(makeMockAWSClient(new RDSClient({})));
      const findings = await scanner.scan();

      const baselineCheckIds = [
        'rds_instance_storage_encrypted',
        'rds_instance_backup_enabled',
        'rds_instance_no_public_access',
        'rds_instance_deletion_protection',
        'rds_instance_multi_az',
        'rds_instance_copy_tags_to_snapshots',
        'rds_instance_enhanced_monitoring_enabled',
        'rds_instance_minor_version_upgrade_enabled',
        'rds_instance_integration_cloudwatch_logs',
        'rds_instance_inside_vpc',
        'rds_instance_extended_support',
        'rds_instance_default_admin',
        'rds_instance_iam_authentication_enabled',
      ];
      const unexpected = findings.filter((f) => baselineCheckIds.includes(f.checkId ?? ''));
      expect(unexpected).toEqual([]);
    });

    it('flags a cluster with a default master username and no deletion protection', async () => {
      rdsMock.on(DescribeDBClustersCommand).resolves({
        DBClusters: [
          safeCluster({
            DBClusterIdentifier: 'cluster-risky',
            MasterUsername: 'admin',
            DeletionProtection: false,
          }),
        ],
      });

      const scanner = new RDSScanner(makeMockAWSClient(new RDSClient({})));
      const findings = await scanner.scan();

      const defaultAdminFinding = findings.find((f) => f.checkId === 'rds_cluster_default_admin');
      expect(defaultAdminFinding).toBeDefined();
      expect(defaultAdminFinding?.evidence).toMatchObject({ clusterId: 'cluster-risky', masterUsername: 'admin' });

      const deletionProtectionFinding = findings.find((f) => f.checkId === 'rds_cluster_deletion_protection');
      expect(deletionProtectionFinding).toBeDefined();
      expect(deletionProtectionFinding?.service).toBe('RDS');
    });

    it('flags an unencrypted DB snapshot and a publicly-restorable snapshot', async () => {
      rdsMock.on(DescribeDBSnapshotsCommand).resolves({
        DBSnapshots: [
          {
            DBSnapshotIdentifier: 'snap-1',
            DBInstanceIdentifier: 'db-safe',
            Engine: 'postgres',
            Encrypted: false,
          },
        ],
      });
      rdsMock.on(DescribeDBSnapshotAttributesCommand).resolves({
        DBSnapshotAttributesResult: {
          DBSnapshotAttributes: [{ AttributeName: 'restore', AttributeValues: ['all'] }],
        },
      });

      const scanner = new RDSScanner(makeMockAWSClient(new RDSClient({})));
      const findings = await scanner.scan();

      const encryptedFinding = findings.find((f) => f.checkId === 'rds_snapshots_encrypted');
      expect(encryptedFinding).toBeDefined();
      expect(encryptedFinding?.evidence).toMatchObject({ snapshotId: 'snap-1', encrypted: false });

      const publicFinding = findings.find((f) => f.checkId === 'rds_snapshots_public_access');
      expect(publicFinding).toBeDefined();
      expect(publicFinding?.evidence).toMatchObject({ snapshotId: 'snap-1', public: true });
    });

    it('flags a CA certificate that has already expired as CRITICAL severity', async () => {
      const expiredDate = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(); // yesterday
      rdsMock.on(DescribeDBInstancesCommand).resolves({
        DBInstances: [safeInstance({ CACertificateIdentifier: 'rds-ca-2019' })],
      });
      rdsMock.on(DescribeCertificatesCommand).resolves({
        Certificates: [{ CertificateIdentifier: 'rds-ca-2019', ValidTill: expiredDate }],
      });

      const scanner = new RDSScanner(makeMockAWSClient(new RDSClient({})));
      const findings = await scanner.scan();

      const certFinding = findings.find((f) => f.checkId === 'rds_instance_certificate_expiration');
      expect(certFinding).toBeDefined();
      expect(certFinding?.severity).toBe('CRITICAL');
      expect(certFinding?.evidence).toMatchObject({ dbId: 'db-safe', certificateId: 'rds-ca-2019' });
    });

    it('flags an instance and cluster not protected by any AWS Backup plan', async () => {
      rdsMock.on(DescribeDBInstancesCommand).resolves({
        DBInstances: [safeInstance({ DBInstanceArn: 'arn:aws:rds:us-east-1:123456789012:db:db-safe' })],
      });
      backupMock.on(ListProtectedResourcesCommand).resolves({ Results: [] });

      const scanner = new RDSScanner(makeMockAWSClient(new RDSClient({})));
      const findings = await scanner.scan();

      const backupFinding = findings.find((f) => f.checkId === 'rds_instance_protected_by_backup_plan');
      expect(backupFinding).toBeDefined();
      expect(backupFinding?.evidence).toMatchObject({ dbId: 'db-safe' });
    });

    it('does not flag backup-plan protection when the instance ARN is covered by AWS Backup', async () => {
      const arn = 'arn:aws:rds:us-east-1:123456789012:db:db-protected';
      rdsMock.on(DescribeDBInstancesCommand).resolves({
        DBInstances: [safeInstance({ DBInstanceIdentifier: 'db-protected', DBInstanceArn: arn })],
      });
      backupMock.on(ListProtectedResourcesCommand).resolves({ Results: [{ ResourceArn: arn }] });

      const scanner = new RDSScanner(makeMockAWSClient(new RDSClient({})));
      const findings = await scanner.scan();

      const backupFinding = findings.find((f) => f.checkId === 'rds_instance_protected_by_backup_plan');
      expect(backupFinding).toBeUndefined();
    });
  });

  describe('scan() — no resources', () => {
    it('returns an empty finding list when there are no instances, clusters, or snapshots', async () => {
      const scanner = new RDSScanner(makeMockAWSClient(new RDSClient({})));
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });
  });

  describe('scan() — pagination', () => {
    it('follows the Marker pagination loop across two pages of DescribeDBInstances', async () => {
      rdsMock
        .on(DescribeDBInstancesCommand)
        .resolvesOnce({
          DBInstances: [safeInstance({ DBInstanceIdentifier: 'db-page-1', StorageEncrypted: false })],
          Marker: 'page-2-token',
        })
        .resolvesOnce({
          DBInstances: [safeInstance({ DBInstanceIdentifier: 'db-page-2', StorageEncrypted: false })],
        });

      const scanner = new RDSScanner(makeMockAWSClient(new RDSClient({})));
      const findings = await scanner.scan();

      const encryptionFindings = findings.filter((f) => f.checkId === 'rds_instance_storage_encrypted');
      const dbIds = encryptionFindings.map((f) => (f.evidence as any).dbId).sort();
      expect(dbIds).toEqual(['db-page-1', 'db-page-2']);

      expect(rdsMock.commandCalls(DescribeDBInstancesCommand)).toHaveLength(2);
    });

    it('follows the Marker pagination loop across two pages of DescribeDBSnapshots', async () => {
      rdsMock
        .on(DescribeDBSnapshotsCommand)
        .resolvesOnce({
          DBSnapshots: [{ DBSnapshotIdentifier: 'snap-page-1', Engine: 'postgres', Encrypted: false }],
          Marker: 'snap-page-2-token',
        })
        .resolvesOnce({
          DBSnapshots: [{ DBSnapshotIdentifier: 'snap-page-2', Engine: 'postgres', Encrypted: false }],
        });

      const scanner = new RDSScanner(makeMockAWSClient(new RDSClient({})));
      const findings = await scanner.scan();

      const snapshotIds = findings
        .filter((f) => f.checkId === 'rds_snapshots_encrypted')
        .map((f) => (f.evidence as any).snapshotId)
        .sort();
      expect(snapshotIds).toEqual(['snap-page-1', 'snap-page-2']);
      expect(rdsMock.commandCalls(DescribeDBSnapshotsCommand)).toHaveLength(2);
    });
  });

  describe('scan() — error handling', () => {
    it('does not throw and still returns instance findings when DescribeDBSnapshots rejects', async () => {
      rdsMock.on(DescribeDBInstancesCommand).resolves({
        DBInstances: [safeInstance({ DBInstanceIdentifier: 'db-with-snap-error', StorageEncrypted: false })],
      });
      rdsMock.on(DescribeDBSnapshotsCommand).rejects(new Error('AccessDenied: rds:DescribeDBSnapshots'));

      const scanner = new RDSScanner(makeMockAWSClient(new RDSClient({})));
      const findings = await scanner.scan();

      const encryptionFinding = findings.find((f) => f.checkId === 'rds_instance_storage_encrypted');
      expect(encryptionFinding).toBeDefined();
      const snapshotFindings = findings.filter((f) => f.checkId === 'rds_snapshots_encrypted');
      expect(snapshotFindings).toEqual([]);
    }, 20000);

    it('returns an empty array (no throw) when DescribeDBInstances itself rejects on every retry', async () => {
      rdsMock.on(DescribeDBInstancesCommand).rejects(new Error('ThrottlingException'));

      const scanner = new RDSScanner(makeMockAWSClient(new RDSClient({})));
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    }, 20000);

    it('skips backup-plan-protection checks (no throw, no finding) when AWS Backup ListProtectedResources rejects', async () => {
      rdsMock.on(DescribeDBInstancesCommand).resolves({ DBInstances: [safeInstance()] });
      backupMock.on(ListProtectedResourcesCommand).rejects(new Error('AccessDenied: backup:ListProtectedResources'));

      const scanner = new RDSScanner(makeMockAWSClient(new RDSClient({})));
      const findings = await scanner.scan();

      const backupFinding = findings.find((f) => f.checkId === 'rds_instance_protected_by_backup_plan');
      expect(backupFinding).toBeUndefined();
    }, 20000);
  });

  describe('scan() — event subscription coverage', () => {
    it('flags missing critical event subscription coverage for DB instances when none are enabled', async () => {
      rdsMock.on(DescribeDBInstancesCommand).resolves({ DBInstances: [safeInstance()] });
      rdsMock.on(DescribeEventSubscriptionsCommand).resolves({ EventSubscriptionsList: [] });

      const scanner = new RDSScanner(makeMockAWSClient(new RDSClient({})));
      const findings = await scanner.scan();

      const subFinding = findings.find((f) => f.checkId === 'rds_instance_critical_event_subscription');
      expect(subFinding).toBeDefined();
      expect(subFinding?.evidence).toMatchObject({ sourceType: 'db-instance' });
    });

    it('does not flag event subscription coverage when a matching enabled subscription covers all events', async () => {
      rdsMock.on(DescribeDBInstancesCommand).resolves({ DBInstances: [safeInstance()] });
      rdsMock.on(DescribeEventSubscriptionsCommand).resolves({
        EventSubscriptionsList: [
          { SourceType: 'db-instance', Enabled: true, EventCategoriesList: [] },
        ],
      });

      const scanner = new RDSScanner(makeMockAWSClient(new RDSClient({})));
      const findings = await scanner.scan();

      const subFinding = findings.find((f) => f.checkId === 'rds_instance_critical_event_subscription');
      expect(subFinding).toBeUndefined();
    });
  });
});
