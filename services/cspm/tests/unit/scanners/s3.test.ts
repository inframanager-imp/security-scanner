import { describe, it, expect, beforeEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  S3Client,
  ListBucketsCommand,
  GetBucketEncryptionCommand,
  GetBucketVersioningCommand,
  GetPublicAccessBlockCommand,
  GetBucketAclCommand,
  GetBucketLoggingCommand,
  GetBucketPolicyCommand,
  GetBucketLocationCommand,
  GetBucketOwnershipControlsCommand,
  GetObjectLockConfigurationCommand,
  GetBucketLifecycleConfigurationCommand,
  GetBucketReplicationCommand,
  GetBucketNotificationConfigurationCommand,
  ListObjectsV2Command,
  HeadBucketCommand,
} from '@aws-sdk/client-s3';
import {
  S3ControlClient,
  GetPublicAccessBlockCommand as GetAccountPublicAccessBlockCommand,
  ListAccessPointsCommand,
  GetAccessPointCommand,
  ListMultiRegionAccessPointsCommand,
} from '@aws-sdk/client-s3-control';
import S3Scanner from '../../../src/scanners/s3';

const s3Mock = mockClient(S3Client);
const s3ControlMock = mockClient(S3ControlClient);

/**
 * Minimal AWSClient stand-in. S3Scanner uses `this.client.s3` directly (the
 * pre-built S3Client on AWSClient) rather than constructing its own, but it
 * does build its own S3ControlClient via `client.getClientConfig()` — both
 * intercepted here via aws-sdk-client-mock regardless of the exact config
 * object passed through.
 */
function makeMockAWSClient(accountId: string | null = '123456789012') {
  return {
    s3: new S3Client({ region: 'us-east-1' }),
    getClientConfig: () => ({ region: 'us-east-1', credentials: {} }),
    getRegion: () => 'us-east-1',
    getAccountId: async () => {
      if (!accountId) throw new Error('no account id');
      return accountId;
    },
  } as any;
}

/** Default "everything empty/clean" stubs so a test only needs to override what it cares about. */
function stubCleanBucketState() {
  s3Mock.on(GetBucketLocationCommand).resolves({ LocationConstraint: 'us-east-1' } as any);
  s3Mock.on(GetBucketVersioningCommand).resolves({ Status: 'Enabled', MFADelete: 'Enabled' } as any);
  s3Mock.on(GetPublicAccessBlockCommand).resolves({
    PublicAccessBlockConfiguration: {
      BlockPublicAcls: true,
      IgnorePublicAcls: true,
      BlockPublicPolicy: true,
      RestrictPublicBuckets: true,
    },
  } as any);
  s3Mock.on(GetBucketAclCommand).resolves({ Grants: [], Owner: { ID: 'owner-canonical-id' } } as any);
  s3Mock.on(GetBucketPolicyCommand).rejects(Object.assign(new Error('NoSuchBucketPolicy'), { name: 'NoSuchBucketPolicy' }));
  s3Mock.on(GetBucketOwnershipControlsCommand).resolves({
    OwnershipControls: { Rules: [{ ObjectOwnership: 'BucketOwnerEnforced' }] },
  } as any);
  s3Mock.on(GetObjectLockConfigurationCommand).resolves({ ObjectLockConfiguration: { ObjectLockEnabled: 'Enabled' } } as any);
  s3Mock.on(GetBucketLifecycleConfigurationCommand).resolves({ Rules: [{ Status: 'Enabled' }] } as any);
  s3Mock.on(GetBucketReplicationCommand).rejects(
    Object.assign(new Error('ReplicationConfigurationNotFoundError'), { name: 'ReplicationConfigurationNotFoundError' })
  );
  s3Mock.on(GetBucketNotificationConfigurationCommand).resolves({ EventBridgeConfiguration: {} } as any);
  s3Mock.on(GetBucketEncryptionCommand).resolves({
    ServerSideEncryptionConfiguration: { Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'aws:kms' } }] },
  } as any);
  s3Mock.on(GetBucketLoggingCommand).resolves({ LoggingEnabled: { TargetBucket: 'log-bucket' } } as any);
  s3Mock.on(ListObjectsV2Command).resolves({ Contents: [] } as any);
  s3Mock.on(HeadBucketCommand).rejects(Object.assign(new Error('NotFound'), { name: 'NotFound', $metadata: { httpStatusCode: 404 } }));

  s3ControlMock.on(GetAccountPublicAccessBlockCommand).resolves({
    PublicAccessBlockConfiguration: {
      BlockPublicAcls: true,
      IgnorePublicAcls: true,
      BlockPublicPolicy: true,
      RestrictPublicBuckets: true,
    },
  } as any);
  s3ControlMock.on(ListAccessPointsCommand).resolves({ AccessPointList: [] } as any);
  s3ControlMock.on(ListMultiRegionAccessPointsCommand).resolves({ AccessPoints: [] } as any);
}

describe('S3Scanner', () => {
  beforeEach(() => {
    s3Mock.reset();
    s3ControlMock.reset();
  });

  describe('scan() — no buckets', () => {
    it('returns an empty result set when the account has no S3 buckets', async () => {
      s3Mock.on(ListBucketsCommand).resolves({ Buckets: [], Owner: { ID: 'owner-canonical-id' } } as any);
      s3ControlMock.on(GetAccountPublicAccessBlockCommand).resolves({
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          IgnorePublicAcls: true,
          BlockPublicPolicy: true,
          RestrictPublicBuckets: true,
        },
      } as any);
      s3ControlMock.on(ListAccessPointsCommand).resolves({ AccessPointList: [] } as any);
      s3ControlMock.on(ListMultiRegionAccessPointsCommand).resolves({ AccessPoints: [] } as any);
      // No buckets of our own to shadow-check, but checkShadowResources still
      // probes predictable service bucket names via HeadBucket in the current
      // region — tell it none of those exist either.
      s3Mock.on(HeadBucketCommand).rejects(
        Object.assign(new Error('NotFound'), { name: 'NotFound', $metadata: { httpStatusCode: 404 } })
      );

      const scanner = new S3Scanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });
  });

  describe('scan() — happy path findings on a single non-compliant bucket', () => {
    it('emits s3_bucket_default_encryption when the bucket has no encryption configuration', async () => {
      s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'my-bucket' }], Owner: { ID: 'owner-canonical-id' } } as any);
      stubCleanBucketState();
      // checkEncryption() only emits a finding on a *successful* response with
      // no rules — it treats a rejected call (e.g. NotFound) as "unknown" and
      // silently skips, matching the source's try/catch-and-log behavior.
      s3Mock.on(GetBucketEncryptionCommand).resolves({ ServerSideEncryptionConfiguration: { Rules: [] } } as any);

      const scanner = new S3Scanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 's3_bucket_default_encryption');
      expect(finding).toBeDefined();
      expect(finding?.service).toBe('S3');
      expect(finding?.evidence).toMatchObject({ bucket: 'my-bucket' });
    });

    it('emits s3_bucket_kms_encryption when the bucket uses SSE-S3 instead of SSE-KMS', async () => {
      s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'sse-s3-bucket' }], Owner: { ID: 'owner-canonical-id' } } as any);
      stubCleanBucketState();
      s3Mock.on(GetBucketEncryptionCommand).resolves({
        ServerSideEncryptionConfiguration: { Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } }] },
      } as any);

      const scanner = new S3Scanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 's3_bucket_kms_encryption');
      expect(finding).toBeDefined();
      expect(finding?.evidence).toMatchObject({ bucket: 'sse-s3-bucket', encryption: 'SSE-S3' });
      // A compliant KMS bucket should not also trigger this finding
      expect(findings.filter((f) => f.checkId === 's3_bucket_default_encryption')).toHaveLength(0);
    });

    it('emits s3_bucket_object_versioning when versioning is not enabled', async () => {
      s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'unversioned-bucket' }], Owner: { ID: 'owner-canonical-id' } } as any);
      stubCleanBucketState();
      s3Mock.on(GetBucketVersioningCommand).resolves({} as any); // no Status field -> not 'Enabled'

      const scanner = new S3Scanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 's3_bucket_object_versioning');
      expect(finding).toBeDefined();
      expect(finding?.evidence).toMatchObject({ bucket: 'unversioned-bucket' });
    });

    it('emits s3_bucket_level_public_access_block when block-public-access settings are incomplete', async () => {
      s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'exposed-bucket' }], Owner: { ID: 'owner-canonical-id' } } as any);
      stubCleanBucketState();
      s3Mock.on(GetPublicAccessBlockCommand).resolves({
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          IgnorePublicAcls: false,
          BlockPublicPolicy: true,
          RestrictPublicBuckets: true,
        },
      } as any);

      const scanner = new S3Scanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 's3_bucket_level_public_access_block');
      expect(finding).toBeDefined();
      expect(finding?.service).toBe('S3');
      expect(finding?.evidence).toMatchObject({ bucket: 'exposed-bucket' });
    });

    it('emits s3_bucket_public_access when the bucket ACL grants access to AllUsers', async () => {
      s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'public-acl-bucket' }], Owner: { ID: 'owner-canonical-id' } } as any);
      stubCleanBucketState();
      s3Mock.on(GetBucketAclCommand).resolves({
        Owner: { ID: 'owner-canonical-id' },
        Grants: [
          {
            Grantee: { Type: 'Group', URI: 'http://acs.amazonaws.com/groups/global/AllUsers' },
            Permission: 'READ',
          },
        ],
      } as any);
      // checkPublicAclPermissions() is skipped both when the account-level PAB
      // already neutralizes public ACLs (ignorePublicAcls && restrictPublicBuckets)
      // and when the bucket-level PAB does the same — relax both so the
      // ACL-driven public-list-acl check actually runs for this test.
      s3ControlMock.on(GetAccountPublicAccessBlockCommand).resolves({
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: false,
          IgnorePublicAcls: false,
          BlockPublicPolicy: false,
          RestrictPublicBuckets: false,
        },
      } as any);
      s3Mock.on(GetPublicAccessBlockCommand).resolves({
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: false,
          IgnorePublicAcls: false,
          BlockPublicPolicy: false,
          RestrictPublicBuckets: false,
        },
      } as any);

      const scanner = new S3Scanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 's3_bucket_public_access');
      expect(finding).toBeDefined();
      expect(finding?.evidence).toMatchObject({ bucket: 'public-acl-bucket', publicGrants: 1 });

      // And the table-driven public-list-ACL check should also fire for the same grant
      const listAclFinding = findings.find((f) => f.checkId === 's3_bucket_public_list_acl');
      expect(listAclFinding).toBeDefined();
      expect(listAclFinding?.evidence).toMatchObject({ bucket: 'public-acl-bucket', permission: 'READ' });
    });

    it('does not emit encryption/versioning/public-access findings for a fully compliant bucket', async () => {
      s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'clean-bucket' }], Owner: { ID: 'owner-canonical-id' } } as any);
      stubCleanBucketState();

      const scanner = new S3Scanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const checkIds = findings.map((f) => f.checkId);
      expect(checkIds).not.toContain('s3_bucket_default_encryption');
      expect(checkIds).not.toContain('s3_bucket_kms_encryption');
      expect(checkIds).not.toContain('s3_bucket_object_versioning');
      expect(checkIds).not.toContain('s3_bucket_level_public_access_block');
      expect(checkIds).not.toContain('s3_bucket_public_access');
      expect(checkIds).not.toContain('s3_bucket_server_access_logging_enabled');
    });
  });

  describe('scan() — pagination', () => {
    it('walks NextToken pagination across two pages of S3 access points', async () => {
      s3Mock.on(ListBucketsCommand).resolves({ Buckets: [], Owner: { ID: 'owner-canonical-id' } } as any);
      s3ControlMock.on(GetAccountPublicAccessBlockCommand).resolves({
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          IgnorePublicAcls: true,
          BlockPublicPolicy: true,
          RestrictPublicBuckets: true,
        },
      } as any);
      s3ControlMock.on(ListMultiRegionAccessPointsCommand).resolves({ AccessPoints: [] } as any);

      s3ControlMock
        .on(ListAccessPointsCommand)
        .resolvesOnce({ AccessPointList: [{ Name: 'ap-page-1', Bucket: 'bucket-a' }], NextToken: 'page-2' } as any)
        .resolvesOnce({ AccessPointList: [{ Name: 'ap-page-2', Bucket: 'bucket-b' }] } as any);

      // Both access points are missing a Block Public Access setting -> both should be flagged
      s3ControlMock.on(GetAccessPointCommand).resolves({
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          IgnorePublicAcls: true,
          BlockPublicPolicy: true,
          RestrictPublicBuckets: false,
        },
      } as any);

      const scanner = new S3Scanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(s3ControlMock).toHaveReceivedCommandTimes(ListAccessPointsCommand, 2);

      const apFindings = findings.filter((f) => f.checkId === 's3_access_point_public_access_block');
      expect(apFindings).toHaveLength(2);
      const flaggedNames = apFindings.map((f) => (f.evidence as any).accessPoint).sort();
      expect(flaggedNames).toEqual(['ap-page-1', 'ap-page-2']);
    });
  });

  describe('scan() — error handling', () => {
    it('does not throw when ListBuckets fails, returning an empty result instead', async () => {
      s3Mock.on(ListBucketsCommand).rejects(new Error('Access Denied'));

      const scanner = new S3Scanner(makeMockAWSClient());
      await expect(scanner.scan()).resolves.toEqual([]);
    });

    it('skips only the affected check when a per-bucket call fails, and still evaluates other checks for that bucket', async () => {
      s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'flaky-bucket' }], Owner: { ID: 'owner-canonical-id' } } as any);
      stubCleanBucketState();
      // Encryption lookup fails outright (not a "not configured" style error) — should be swallowed, no finding either way
      s3Mock.on(GetBucketEncryptionCommand).rejects(new Error('InternalServiceError'));
      // Versioning is still broken, so that check should still fire normally
      s3Mock.on(GetBucketVersioningCommand).resolves({} as any);

      const scanner = new S3Scanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const checkIds = findings.map((f) => f.checkId);
      expect(checkIds).not.toContain('s3_bucket_default_encryption');
      expect(checkIds).not.toContain('s3_bucket_kms_encryption');
      expect(checkIds).toContain('s3_bucket_object_versioning');
    });

    it('does not throw when the whole scan is invoked against an account with no resolvable account id', async () => {
      s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'no-account-bucket' }], Owner: { ID: 'owner-canonical-id' } } as any);
      stubCleanBucketState();

      const scanner = new S3Scanner(makeMockAWSClient(null));
      await expect(scanner.scan()).resolves.toBeInstanceOf(Array);
    });
  });
});
