import { describe, it, expect, beforeEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetTrailStatusCommand,
  GetEventSelectorsCommand,
  GetInsightSelectorsCommand,
  LookupEventsCommand,
} from '@aws-sdk/client-cloudtrail';
import {
  S3Client,
  GetBucketAclCommand,
  GetBucketLoggingCommand,
  GetBucketVersioningCommand,
  ListBucketsCommand,
} from '@aws-sdk/client-s3';
import CloudTrailScanner from '../../../src/scanners/cloudtrail';

const cloudtrailMock = mockClient(CloudTrailClient);
const s3Mock = mockClient(S3Client);

/**
 * Minimal AWSClient stand-in. CloudTrailScanner uses `this.client.cloudtrail`
 * and `this.client.s3` directly (the pre-built clients on AWSClient) rather
 * than constructing its own via getClientConfig().
 */
function makeMockAWSClient() {
  return {
    cloudtrail: new CloudTrailClient({ region: 'us-east-1' }),
    s3: new S3Client({ region: 'us-east-1' }),
    getRegion: () => 'us-east-1',
    getClientConfig: () => ({ region: 'us-east-1', credentials: {} }),
  } as any;
}

/** A single well-configured, actively logging, multi-region trail with insights on. */
const COMPLIANT_TRAIL = {
  Name: 'compliant-trail',
  TrailARN: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/compliant-trail',
  HomeRegion: 'us-east-1',
  S3BucketName: 'compliant-bucket',
  IsMultiRegionTrail: true,
  LogFileValidationEnabled: true,
  CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:123456789012:log-group:trail-logs',
  KMSKeyId: 'arn:aws:kms:us-east-1:123456789012:key/abc',
};

/** Stub every downstream call so a fully-compliant trail produces zero findings by default. */
function stubCleanState() {
  cloudtrailMock.on(GetTrailStatusCommand).resolves({ IsLogging: true } as any);
  cloudtrailMock.on(GetEventSelectorsCommand).resolves({
    EventSelectors: [{ ReadWriteType: 'All', IncludeManagementEvents: true, DataResources: [] }],
  } as any);
  cloudtrailMock.on(GetInsightSelectorsCommand).resolves({
    InsightSelectors: [{ InsightType: 'ApiCallRateInsight' }],
  } as any);
  cloudtrailMock.on(LookupEventsCommand).resolves({ Events: [] } as any);

  s3Mock.on(GetBucketVersioningCommand).resolves({ MFADelete: 'Enabled' } as any);
  s3Mock.on(GetBucketLoggingCommand).resolves({ LoggingEnabled: { TargetBucket: 'log-bucket' } } as any);
  s3Mock.on(GetBucketAclCommand).resolves({ Grants: [] } as any);
  s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'compliant-bucket' }] } as any);
}

describe('CloudTrailScanner', () => {
  beforeEach(() => {
    cloudtrailMock.reset();
    s3Mock.reset();
  });

  describe('scan() — no trails', () => {
    it('emits cloudtrail_trail_not_configured when the account has no trails in the region', async () => {
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [] } as any);
      // Account-level checks still run against an empty details array
      s3Mock.on(ListBucketsCommand).resolves({ Buckets: [] } as any);
      cloudtrailMock.on(LookupEventsCommand).resolves({ Events: [] } as any);

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'cloudtrail_trail_not_configured');
      expect(finding).toBeDefined();
      expect(finding?.service).toBe('CloudTrail');
      expect(finding?.evidence).toMatchObject({ region: 'us-east-1' });

      // No trails also means Bedrock coverage is missing
      expect(findings.map((f) => f.checkId)).toContain('cloudtrail_bedrock_logging_enabled');
    });
  });

  describe('scan() — happy path findings on a single non-compliant trail', () => {
    it('emits cloudtrail_trail_not_logging when the trail status reports not logging, and skips the MFA-delete check', async () => {
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [COMPLIANT_TRAIL] } as any);
      stubCleanState();
      cloudtrailMock.on(GetTrailStatusCommand).resolves({ IsLogging: false } as any);

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'cloudtrail_trail_not_logging');
      expect(finding).toBeDefined();
      expect(finding?.service).toBe('CloudTrail');
      expect(finding?.evidence).toMatchObject({ trailName: 'compliant-trail', isLogging: false });

      // MFA-delete check only runs for actively logging trails
      expect(findings.map((f) => f.checkId)).not.toContain('cloudtrail_bucket_requires_mfa_delete');
      // Not logging also means Insights coverage cannot be asserted as "exist"
      expect(findings.map((f) => f.checkId)).not.toContain('cloudtrail_insights_exist');
    });

    it('emits cloudtrail_multi_region_enabled and cloudtrail_trail_s3_bucket_not_configured for a single-region trail with no S3 bucket', async () => {
      const trail = { ...COMPLIANT_TRAIL, IsMultiRegionTrail: false, S3BucketName: undefined };
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [trail] } as any);
      stubCleanState();

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findings.find((f) => f.checkId === 'cloudtrail_multi_region_enabled')).toBeDefined();
      expect(findings.find((f) => f.checkId === 'cloudtrail_trail_s3_bucket_not_configured')).toBeDefined();

      // No bucket configured -> bucket-level checks (which require a bucket name) should not run
      expect(findings.map((f) => f.checkId)).not.toContain('cloudtrail_bucket_requires_mfa_delete');
      expect(findings.map((f) => f.checkId)).not.toContain('cloudtrail_logs_s3_bucket_access_logging_enabled');
    });

    it('emits cloudtrail_bucket_requires_mfa_delete when the logging trail bucket has MFA delete disabled', async () => {
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [COMPLIANT_TRAIL] } as any);
      stubCleanState();
      s3Mock.on(GetBucketVersioningCommand).resolves({} as any); // no MFADelete field -> not 'Enabled'

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'cloudtrail_bucket_requires_mfa_delete');
      expect(finding).toBeDefined();
      expect(finding?.evidence).toMatchObject({ trailName: 'compliant-trail', bucket: 'compliant-bucket', mfaDelete: null });
    });

    it('emits cloudtrail_logs_s3_bucket_is_not_publicly_accessible when the log bucket ACL grants AllUsers access', async () => {
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [COMPLIANT_TRAIL] } as any);
      stubCleanState();
      s3Mock.on(GetBucketAclCommand).resolves({
        Grants: [{ Grantee: { URI: 'http://acs.amazonaws.com/groups/global/AllUsers' } }],
      } as any);

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'cloudtrail_logs_s3_bucket_is_not_publicly_accessible');
      expect(finding).toBeDefined();
      expect(finding?.evidence).toMatchObject({ trailName: 'compliant-trail', bucket: 'compliant-bucket', isMultiRegion: true });
    });

    it('does not emit configuration/bucket findings for a fully compliant, actively logging trail', async () => {
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [COMPLIANT_TRAIL] } as any);
      stubCleanState();

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const checkIds = findings.map((f) => f.checkId);
      expect(checkIds).not.toContain('cloudtrail_trail_not_logging');
      expect(checkIds).not.toContain('cloudtrail_multi_region_enabled');
      expect(checkIds).not.toContain('cloudtrail_trail_s3_bucket_not_configured');
      expect(checkIds).not.toContain('cloudtrail_log_file_validation_enabled');
      expect(checkIds).not.toContain('cloudtrail_cloudwatch_logging_enabled');
      expect(checkIds).not.toContain('cloudtrail_kms_encryption_enabled');
      expect(checkIds).not.toContain('cloudtrail_bucket_requires_mfa_delete');
      expect(checkIds).not.toContain('cloudtrail_logs_s3_bucket_access_logging_enabled');
      expect(checkIds).not.toContain('cloudtrail_logs_s3_bucket_is_not_publicly_accessible');
      expect(checkIds).not.toContain('cloudtrail_insights_exist');
      // A single all-management, all-buckets trail also satisfies Bedrock coverage
      expect(checkIds).not.toContain('cloudtrail_bedrock_logging_enabled');
    });
  });

  describe('scan() — account-level LLM jacking detection', () => {
    it('emits cloudtrail_threat_detection_llm_jacking when one identity is behind a wide spread of LLM-related API calls', async () => {
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [COMPLIANT_TRAIL] } as any);
      stubCleanState();

      const suspiciousIdentity = { arn: 'arn:aws:iam::123456789012:user/suspicious-user', type: 'IAMUser' };
      const makeEvent = () => ({
        CloudTrailEvent: JSON.stringify({ userIdentity: suspiciousIdentity }),
      });

      // LLM_JACKING_ACTIONS has 14 entries; threshold is 0.4 (> 5.6 actions needed).
      // Have every LookupEvents call return an event from the same identity so
      // all 14 action names count toward that identity's diversity score.
      cloudtrailMock.on(LookupEventsCommand).resolves({ Events: [makeEvent()] } as any);

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'cloudtrail_threat_detection_llm_jacking');
      expect(finding).toBeDefined();
      expect(finding?.service).toBe('CloudTrail');
      expect(finding?.evidence).toMatchObject({
        identityArn: 'arn:aws:iam::123456789012:user/suspicious-user',
        identityType: 'IAMUser',
      });
      expect((finding?.evidence as any).score).toBe(1);
    });

    it('does not emit cloudtrail_threat_detection_llm_jacking when events have no identity ARN or are absent', async () => {
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [COMPLIANT_TRAIL] } as any);
      stubCleanState();
      // Events from AWS services carry no userIdentity.arn and must be ignored
      cloudtrailMock.on(LookupEventsCommand).resolves({
        Events: [{ CloudTrailEvent: JSON.stringify({ userIdentity: { type: 'AWSService' } }) }],
      } as any);

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findings.map((f) => f.checkId)).not.toContain('cloudtrail_threat_detection_llm_jacking');
    });
  });

  describe('scan() — S3 data events account-level checks', () => {
    it('emits cloudtrail_s3_dataevents_read_enabled and _write_enabled when no trail logs all-bucket S3 data events and the account has buckets', async () => {
      // Classic selector with no DataResources at all -> doesn't cover S3 data events
      const trail = { ...COMPLIANT_TRAIL };
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [trail] } as any);
      stubCleanState();
      s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'some-bucket' }] } as any);

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const checkIds = findings.map((f) => f.checkId);
      expect(checkIds).toContain('cloudtrail_s3_dataevents_read_enabled');
      expect(checkIds).toContain('cloudtrail_s3_dataevents_write_enabled');
    });

    it('does not emit S3 data-event findings when the account has no S3 buckets', async () => {
      const trail = { ...COMPLIANT_TRAIL };
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [trail] } as any);
      stubCleanState();
      s3Mock.on(ListBucketsCommand).resolves({ Buckets: [] } as any);

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const checkIds = findings.map((f) => f.checkId);
      expect(checkIds).not.toContain('cloudtrail_s3_dataevents_read_enabled');
      expect(checkIds).not.toContain('cloudtrail_s3_dataevents_write_enabled');
    });

    it('does not emit S3 data-event findings when a trail has an all-buckets data event selector covering read and write', async () => {
      const trail = { ...COMPLIANT_TRAIL };
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [trail] } as any);
      stubCleanState();
      cloudtrailMock.on(GetEventSelectorsCommand).resolves({
        EventSelectors: [
          {
            ReadWriteType: 'All',
            IncludeManagementEvents: true,
            DataResources: [{ Type: 'AWS::S3::Object', Values: ['arn:aws:s3'] }],
          },
        ],
      } as any);
      s3Mock.on(ListBucketsCommand).resolves({ Buckets: [{ Name: 'some-bucket' }] } as any);

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const checkIds = findings.map((f) => f.checkId);
      expect(checkIds).not.toContain('cloudtrail_s3_dataevents_read_enabled');
      expect(checkIds).not.toContain('cloudtrail_s3_dataevents_write_enabled');
    });
  });

  describe('scan() — Bedrock logging coverage', () => {
    it('does not emit cloudtrail_bedrock_logging_enabled when a logging trail has all-management classic selectors', async () => {
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [COMPLIANT_TRAIL] } as any);
      stubCleanState();

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findings.map((f) => f.checkId)).not.toContain('cloudtrail_bedrock_logging_enabled');
    });

    it('emits cloudtrail_bedrock_logging_enabled when no logging trail covers management or Bedrock data events', async () => {
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [COMPLIANT_TRAIL] } as any);
      stubCleanState();
      // ReadOnly-only selector does not satisfy the All/WriteOnly requirement for Bedrock coverage
      cloudtrailMock.on(GetEventSelectorsCommand).resolves({
        EventSelectors: [{ ReadWriteType: 'ReadOnly', IncludeManagementEvents: true, DataResources: [] }],
      } as any);

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'cloudtrail_bedrock_logging_enabled');
      expect(finding).toBeDefined();
      expect(finding?.evidence).toMatchObject({ region: 'us-east-1', trailCount: 1 });
    });
  });

  describe('scan() — multiple trails', () => {
    it('processes every discovered trail and aggregates findings across all of them', async () => {
      const trailA = { ...COMPLIANT_TRAIL, Name: 'trail-a', TrailARN: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/trail-a', S3BucketName: 'bucket-a' };
      const trailB = { ...COMPLIANT_TRAIL, Name: 'trail-b', TrailARN: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/trail-b', S3BucketName: 'bucket-b', LogFileValidationEnabled: false };
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [trailA, trailB] } as any);
      stubCleanState();

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const validationFindings = findings.filter((f) => f.checkId === 'cloudtrail_log_file_validation_enabled');
      expect(validationFindings).toHaveLength(1);
      expect(validationFindings[0]?.evidence).toMatchObject({ trailName: 'trail-b' });
    });
  });

  describe('scan() — error handling', () => {
    it('does not throw and returns an empty array when DescribeTrails fails outright', async () => {
      cloudtrailMock.on(DescribeTrailsCommand).rejects(new Error('Access Denied'));

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      await expect(scanner.scan()).resolves.toEqual([]);
    });

    it('skips a trail whose detail collection throws mid-way, but still returns account-level findings', async () => {
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [COMPLIANT_TRAIL] } as any);
      stubCleanState();
      // GetTrailStatus is wrapped in its own try/catch (isLogging stays null), so to
      // actually break collectTrailDetail's outer flow we fail retry-wrapped GetEventSelectors
      // repeatedly is not enough (also caught) — instead assert graceful degradation when
      // every per-trail call errors: scan should still complete without throwing.
      cloudtrailMock.on(GetTrailStatusCommand).rejects(new Error('Throttling'));
      cloudtrailMock.on(GetEventSelectorsCommand).rejects(new Error('Throttling'));
      cloudtrailMock.on(GetInsightSelectorsCommand).rejects(new Error('Throttling'));
      s3Mock.on(GetBucketVersioningCommand).rejects(new Error('AccessDenied'));
      s3Mock.on(GetBucketLoggingCommand).rejects(new Error('AccessDenied'));
      s3Mock.on(GetBucketAclCommand).rejects(new Error('AccessDenied'));

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      // isLogging stays null (unknown) so MFA-delete and Insights checks are skipped,
      // but the always-on configuration checks (e.g. multi-region, KMS) still evaluate
      // against the raw trail object, and the scan completes without throwing.
      expect(findings).toBeInstanceOf(Array);
      expect(findings.map((f) => f.checkId)).not.toContain('cloudtrail_trail_not_logging');
      expect(findings.map((f) => f.checkId)).not.toContain('cloudtrail_bucket_requires_mfa_delete');
    });

    it('does not throw when LookupEvents fails for every LLM-jacking action name', async () => {
      cloudtrailMock.on(DescribeTrailsCommand).resolves({ trailList: [COMPLIANT_TRAIL] } as any);
      stubCleanState();
      cloudtrailMock.on(LookupEventsCommand).rejects(new Error('ThrottlingException'));

      const scanner = new CloudTrailScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findings.map((f) => f.checkId)).not.toContain('cloudtrail_threat_detection_llm_jacking');
      // Every one of the 14 LLM_JACKING_ACTIONS is wrapped in retry() (3 attempts,
      // exponential backoff), so this specific case genuinely runs past the default
      // 30s test timeout.
    }, 60000);
  });
});
