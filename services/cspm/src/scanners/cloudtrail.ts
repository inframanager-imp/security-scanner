// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  DescribeTrailsCommand,
  GetTrailStatusCommand,
  GetEventSelectorsCommand,
  GetInsightSelectorsCommand,
  LookupEventsCommand,
} from '@aws-sdk/client-cloudtrail';
import {
  GetBucketAclCommand,
  GetBucketLoggingCommand,
  GetBucketVersioningCommand,
  ListBucketsCommand,
} from '@aws-sdk/client-s3';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

/** Per-trail state gathered once and shared by every check (ports Prowler's Trail model). */
interface TrailDetail {
  trail: any;
  name: string;
  arn: string;
  homeRegion: string;
  s3Bucket: string;
  isMultiRegion: boolean;
  /** null = GetTrailStatus failed (unknown) */
  isLogging: boolean | null;
  /** Classic event selectors (empty when the trail uses advanced selectors) */
  eventSelectors: any[];
  /** Advanced event selectors (empty when the trail uses classic selectors) */
  advancedEventSelectors: any[];
  /** null = GetInsightSelectors failed for a reason other than "insights not enabled" */
  hasInsightSelectors: boolean | null;
}

const PUBLIC_ACL_URI = 'http://acs.amazonaws.com/groups/global/AllUsers';

// Bedrock resource types supported by CloudTrail advanced event selectors (Prowler port)
const BEDROCK_RESOURCE_TYPES = [
  'AWS::Bedrock::AgentAlias',
  'AWS::Bedrock::FlowAlias',
  'AWS::Bedrock::Guardrail',
  'AWS::Bedrock::InlineAgent',
  'AWS::Bedrock::KnowledgeBase',
  'AWS::Bedrock::Model',
  'AWS::Bedrock::Prompt',
];

// Bedrock control-plane event sources, including Bedrock Data Automation (Prowler port)
const BEDROCK_EVENT_SOURCES = [
  'bedrock.amazonaws.com',
  'bedrock-agent.amazonaws.com',
  'bedrock-runtime.amazonaws.com',
  'bedrock-agent-runtime.amazonaws.com',
  'bedrock-data-automation.amazonaws.com',
  'bedrock-data-automation-runtime.amazonaws.com',
];

// cloudtrail_s3_dataevents_* family is table-driven: same selector walk, different ReadWriteType set
const S3_DATA_EVENT_CHECKS: { checkId: string; readWriteTypes: string[]; label: string }[] = [
  { checkId: 'cloudtrail_s3_dataevents_read_enabled',  readWriteTypes: ['ReadOnly', 'All'],  label: 'read' },
  { checkId: 'cloudtrail_s3_dataevents_write_enabled', readWriteTypes: ['WriteOnly', 'All'], label: 'write' },
];

// LLM jacking detection defaults (Prowler port)
const LLM_JACKING_ACTIONS = [
  'PutUseCaseForModelAccess',
  'PutFoundationModelEntitlement',
  'PutModelInvocationLoggingConfiguration',
  'CreateFoundationModelAgreement',
  'InvokeModel',
  'InvokeModelWithResponseStream',
  'GetUseCaseForModelAccess',
  'GetModelInvocationLoggingConfiguration',
  'GetFoundationModelAvailability',
  'ListFoundationModelAgreementOffers',
  'ListFoundationModels',
  'ListProvisionedModelThroughputs',
  'SearchAgreements',
  'AcceptAgreementRequest',
];
const LLM_JACKING_THRESHOLD = 0.4;
const LLM_JACKING_WINDOW_MINUTES = 1440;

/** All selectors declared for a field must accept the candidate value (Prowler port). */
function selectorsMatchValue(value: string, selectors: any[]): boolean {
  return selectors.length > 0 && selectors.every(s => fieldSelectorMatchesValue(value, s));
}

/** Evaluate one CloudTrail advanced field selector against a candidate value (Prowler port). */
function fieldSelectorMatchesValue(value: string, selector: any): boolean {
  const conditions: boolean[] = [];
  if (selector.Equals) conditions.push(selector.Equals.includes(value));
  if (selector.NotEquals) conditions.push(!selector.NotEquals.includes(value));
  if (selector.StartsWith) conditions.push(selector.StartsWith.some((p: string) => value.startsWith(p)));
  if (selector.NotStartsWith) conditions.push(selector.NotStartsWith.every((p: string) => !value.startsWith(p)));
  if (selector.EndsWith) conditions.push(selector.EndsWith.some((s: string) => value.endsWith(s)));
  if (selector.NotEndsWith) conditions.push(selector.NotEndsWith.every((s: string) => !value.endsWith(s)));
  return conditions.length > 0 ? conditions.every(Boolean) : true;
}

export class CloudTrailScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'CloudTrail');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting CloudTrail security scan...');

      // Discover all trails
      const trails = await this.discoverTrails();
      const details: TrailDetail[] = [];

      if (trails.length === 0) {
        findings.push(this.emit(
          'cloudtrail_trail_not_configured',
          { region: this.client.getRegion() },
          {
            message: 'CloudTrail is not configured in this region',
          }
        ));
      }

      // Check each trail configuration
      for (const trail of trails) {
        const trailName = trail.Name || trail.TrailARN?.split('/')?.pop() || 'Unknown';
        try {
          const detail = await this.collectTrailDetail(trail);
          details.push(detail);
          findings.push(...this.validateTrailConfiguration(detail));
          findings.push(...(await this.validateTrailBucket(detail)));
        } catch (error) {
          logger.warn(`Failed to validate trail ${trailName}`, { error: (error as Error).message });
        }
      }

      // Account-level checks that evaluate across all trails
      findings.push(...this.checkBedrockLogging(details));
      findings.push(...(await this.checkS3DataEvents(details)));
      findings.push(...(await this.checkLlmJacking()));

      logger.info(`CloudTrail scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('CloudTrail scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async discoverTrails(): Promise<any[]> {
    return retry(async () => {
      logger.debug('Discovering CloudTrail trails...');

      const describeCmd = new DescribeTrailsCommand({
        includeShadowTrails: true
      });
      const result = await this.client.cloudtrail.send(describeCmd);

      return result.trailList || [];
    });
  }

  /** Fetch trail status, event selectors and insight selectors once per trail. */
  private async collectTrailDetail(trail: any): Promise<TrailDetail> {
    const name = trail.Name || trail.TrailARN?.split('/')?.pop() || 'Unknown';
    // The Get* APIs accept the trail ARN, which also works for shadow trails homed in another region
    const trailRef = trail.TrailARN || name;

    const detail: TrailDetail = {
      trail,
      name,
      arn: trail.TrailARN || name,
      homeRegion: trail.HomeRegion || this.client.getRegion(),
      s3Bucket: trail.S3BucketName || '',
      isMultiRegion: !!trail.IsMultiRegionTrail,
      isLogging: null,
      eventSelectors: [],
      advancedEventSelectors: [],
      hasInsightSelectors: null,
    };

    try {
      const status: any = await retry(async () => {
        return await this.client.cloudtrail.send(new GetTrailStatusCommand({ Name: trailRef }));
      });
      detail.isLogging = !!status.IsLogging;
    } catch (error) {
      logger.debug(`Failed to get status for trail ${name}`, { error: (error as Error).message });
    }

    try {
      const selectors: any = await retry(async () => {
        return await this.client.cloudtrail.send(new GetEventSelectorsCommand({ TrailName: trailRef }));
      });
      // Prowler: classic selectors take precedence; advanced ones only apply when no classic exist
      if (selectors.EventSelectors?.length) {
        detail.eventSelectors = selectors.EventSelectors;
      } else if (selectors.AdvancedEventSelectors?.length) {
        detail.advancedEventSelectors = selectors.AdvancedEventSelectors;
      }
    } catch (error) {
      logger.debug(`Failed to get event selectors for trail ${name}`, { error: (error as Error).message });
    }

    try {
      // No retry: InsightNotEnabledException is the common (expected) outcome
      const insights: any = await this.client.cloudtrail.send(new GetInsightSelectorsCommand({ TrailName: trailRef }));
      detail.hasInsightSelectors = (insights.InsightSelectors ?? []).length > 0;
    } catch (error: any) {
      if (error?.name === 'InsightNotEnabledException') {
        detail.hasInsightSelectors = false;
      } else {
        logger.debug(`Failed to get insight selectors for trail ${name}`, { error: (error as Error).message });
      }
    }

    return detail;
  }

  private validateTrailConfiguration(detail: TrailDetail): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const trail = detail.trail;
    const trailName = detail.name;

    // Check if trail is logging
    if (detail.isLogging === false) {
      findings.push(this.emit(
        'cloudtrail_trail_not_logging',
        { trailName, isLogging: false },
        {
          message: `Trail "${trailName}" is not actively logging events`,
          remediation: `Enable logging for trail "${trailName}" to ensure all API calls are recorded`,
        }
      ));
    }

    // Check multi-region
    if (!trail.IsMultiRegionTrail) {
      findings.push(this.emit(
        'cloudtrail_multi_region_enabled',
        { trailName, isMultiRegion: trail.IsMultiRegionTrail },
        {
          message: `Trail "${trailName}" is not multi-region. API activity in other regions may not be logged.`,
          remediation: `Enable multi-region logging for trail "${trailName}"`,
        }
      ));
    }

    // Check S3 logging
    if (!trail.S3BucketName) {
      findings.push(this.emit(
        'cloudtrail_trail_s3_bucket_not_configured',
        { trailName, s3Bucket: trail.S3BucketName },
        {
          message: `Trail "${trailName}" is not logging to an S3 bucket`,
          remediation: `Configure S3 bucket logging for trail "${trailName}"`,
        }
      ));
    }

    // Check log file validation
    if (!trail.LogFileValidationEnabled) {
      findings.push(this.emit(
        'cloudtrail_log_file_validation_enabled',
        { trailName, logFileValidation: trail.LogFileValidationEnabled },
        {
          message: `Trail "${trailName}" does not have log file validation enabled`,
          remediation: `Enable log file validation for trail "${trailName}" to detect unauthorized modifications`,
        }
      ));
    }

    // Check CloudWatch Logs
    if (!trail.CloudWatchLogsLogGroupArn) {
      findings.push(this.emit(
        'cloudtrail_cloudwatch_logging_enabled',
        { trailName, cwLogs: trail.CloudWatchLogsLogGroupArn },
        {
          message: `Trail "${trailName}" is not logging to CloudWatch Logs for real-time monitoring`,
          remediation: `Configure CloudWatch Logs destination for trail "${trailName}" for real-time alerts`,
        }
      ));
    }

    // Check KMS encryption
    if (!trail.KMSKeyId) {
      findings.push(this.emit(
        'cloudtrail_kms_encryption_enabled',
        { trailName, kmsKey: trail.KMSKeyId },
        {
          message: `Trail "${trailName}" S3 logs may not be using KMS encryption`,
          remediation: `Enable KMS encryption for S3 logs of trail "${trailName}"`,
        }
      ));
    }

    // Check management events (classic selectors only, matching the original intent)
    if (detail.eventSelectors.length > 0) {
      const hasManagementEvents = detail.eventSelectors.some((es: any) => es.IncludeManagementEvents);
      if (!hasManagementEvents) {
        findings.push(this.emit(
          'cloudtrail_multi_region_enabled_logging_management_events',
          { trailName, eventSelectors: detail.eventSelectors },
          {
            message: `Trail "${trailName}" is not logging management events`,
            remediation: `Enable management event logging for trail "${trailName}"`,
          }
        ));
      }
    }

    // cloudtrail_insights_exist: logging trails should have Insights selectors
    if (detail.isLogging === true && detail.hasInsightSelectors === false) {
      findings.push(this.emit(
        'cloudtrail_insights_exist',
        { trailName, homeRegion: detail.homeRegion, hasInsightSelectors: false },
        {
          message: `Trail "${trailName}" is actively logging but does not have CloudTrail Insights enabled`,
          remediation: `Enable CloudTrail Insights (ApiCallRateInsight and ApiErrorRateInsight) on trail "${trailName}"`,
        }
      ));
    }

    return findings;
  }

  /**
   * Checks against the trail's destination S3 bucket. When the bucket lives in
   * another account/region the S3 calls fail and the check is skipped (Prowler
   * reports these as MANUAL; we only emit failing findings).
   */
  private async validateTrailBucket(detail: TrailDetail): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const bucket = detail.s3Bucket;
    const trailName = detail.name;
    if (!bucket) return findings;

    // cloudtrail_bucket_requires_mfa_delete: only evaluated for actively logging trails
    if (detail.isLogging === true) {
      try {
        const versioning: any = await retry(async () => {
          return await this.client.s3.send(new GetBucketVersioningCommand({ Bucket: bucket }));
        });
        if (versioning.MFADelete !== 'Enabled') {
          findings.push(this.emit(
            'cloudtrail_bucket_requires_mfa_delete',
            { trailName, bucket, mfaDelete: versioning.MFADelete ?? null },
            {
              message: `Trail "${trailName}" log bucket "${bucket}" does not have MFA delete enabled`,
              remediation: `Enable MFA delete on bucket "${bucket}": aws s3api put-bucket-versioning --bucket ${bucket} --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa "<mfa-serial> <code>"`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Cannot read versioning of CloudTrail bucket ${bucket} (cross-account or inaccessible), skipping MFA delete check`, { error: (error as Error).message });
      }
    }

    // cloudtrail_logs_s3_bucket_access_logging_enabled
    try {
      const loggingResult: any = await retry(async () => {
        return await this.client.s3.send(new GetBucketLoggingCommand({ Bucket: bucket }));
      });
      if (!loggingResult.LoggingEnabled) {
        findings.push(this.emit(
          'cloudtrail_logs_s3_bucket_access_logging_enabled',
          { trailName, bucket, isMultiRegion: detail.isMultiRegion },
          {
            message: `${detail.isMultiRegion ? 'Multiregion trail' : 'Single region trail'} "${trailName}" S3 bucket access logging is not enabled for bucket "${bucket}"`,
            remediation: `Enable S3 server access logging on bucket "${bucket}", delivering the access logs to a separate tightly-controlled bucket`,
          }
        ));
      }
    } catch (error) {
      logger.debug(`Cannot read logging config of CloudTrail bucket ${bucket} (cross-account or inaccessible), skipping access logging check`, { error: (error as Error).message });
    }

    // cloudtrail_logs_s3_bucket_is_not_publicly_accessible
    try {
      const acl: any = await retry(async () => {
        return await this.client.s3.send(new GetBucketAclCommand({ Bucket: bucket }));
      });
      const isPublic = (acl.Grants ?? []).some((grant: any) => grant?.Grantee?.URI === PUBLIC_ACL_URI);
      if (isPublic) {
        findings.push(this.emit(
          'cloudtrail_logs_s3_bucket_is_not_publicly_accessible',
          { trailName, bucket, isMultiRegion: detail.isMultiRegion },
          {
            message: `S3 bucket "${bucket}" receiving logs from ${detail.isMultiRegion ? 'multiregion' : 'single region'} trail "${trailName}" is publicly accessible (ACL grants access to AllUsers)`,
            remediation: `Remove the public ACL grant from bucket "${bucket}" (aws s3api put-bucket-acl --bucket ${bucket} --acl private) and enable S3 Block Public Access`,
          }
        ));
      }
    } catch (error) {
      logger.debug(`Cannot read ACL of CloudTrail bucket ${bucket} (cross-account or inaccessible), skipping public access check`, { error: (error as Error).message });
    }

    return findings;
  }

  /** cloudtrail_bedrock_logging_enabled: at least one logging trail must capture Bedrock API activity. */
  private checkBedrockLogging(details: TrailDetail[]): ScanningResult[] {
    const covered = details.some(detail => detail.isLogging === true && this.trailLogsBedrock(detail));
    if (covered) return [];

    return [this.emit(
      'cloudtrail_bedrock_logging_enabled',
      { region: this.client.getRegion(), trailCount: details.length },
      {
        message: 'No CloudTrail trails are configured to log Amazon Bedrock API calls',
        remediation: 'Enable management events on an actively logging trail, or add advanced event selectors targeting Bedrock resource types (AWS::Bedrock::Model, AWS::Bedrock::Guardrail, ...)',
      }
    )];
  }

  private trailLogsBedrock(detail: TrailDetail): boolean {
    // Classic selectors: management events with All/WriteOnly cover Bedrock control-plane calls
    for (const selector of detail.eventSelectors) {
      const includeManagement = selector.IncludeManagementEvents ?? true;
      const readWriteType = selector.ReadWriteType ?? 'All';
      if (includeManagement && (readWriteType === 'All' || readWriteType === 'WriteOnly')) return true;
    }
    // Advanced selectors: management events (unless restricted to read-only or non-Bedrock sources)
    // or data events targeting a Bedrock resource type
    for (const selector of detail.advancedEventSelectors) {
      const fieldSelectors: any[] = selector.FieldSelectors ?? [];
      if (this.logsAdvancedManagementEvents(fieldSelectors)) return true;
      if (this.logsAdvancedBedrockDataEvents(fieldSelectors)) return true;
    }
    return false;
  }

  private logsAdvancedManagementEvents(fieldSelectors: any[]): boolean {
    const eventCategorySelectors = fieldSelectors.filter(f => f.Field === 'eventCategory');
    if (!selectorsMatchValue('Management', eventCategorySelectors)) return false;

    const readOnlySelectors = fieldSelectors.filter(f => f.Field === 'readOnly');
    const hasReadOnlyRestriction =
      readOnlySelectors.length > 0 &&
      !readOnlySelectors.some(s => fieldSelectorMatchesValue('false', s));
    if (hasReadOnlyRestriction) return false;

    const eventSourceSelectors = fieldSelectors.filter(f => f.Field === 'eventSource');
    if (eventSourceSelectors.length === 0) return true;
    return BEDROCK_EVENT_SOURCES.some(source => selectorsMatchValue(source, eventSourceSelectors));
  }

  private logsAdvancedBedrockDataEvents(fieldSelectors: any[]): boolean {
    const eventCategorySelectors = fieldSelectors.filter(f => f.Field === 'eventCategory');
    if (!selectorsMatchValue('Data', eventCategorySelectors)) return false;

    const resourceTypeSelectors = fieldSelectors.filter(f => f.Field === 'resources.type');
    return BEDROCK_RESOURCE_TYPES.some(type => selectorsMatchValue(type, resourceTypeSelectors));
  }

  /** cloudtrail_s3_dataevents_{read,write}_enabled: table-driven account-level checks. */
  private async checkS3DataEvents(details: TrailDetail[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const firstArn = details[0]?.arn ?? '';
    const partition = firstArn.startsWith('arn:') ? firstArn.split(':')[1] : 'aws';
    const allBucketsValues = [
      `arn:${partition}:s3`,
      `arn:${partition}:s3:::`,
      `arn:${partition}:s3:::*/*`,
    ];

    let hasBuckets: boolean | null = null; // lazily fetched once, shared by both checks

    for (const check of S3_DATA_EVENT_CHECKS) {
      const covered = details.some(detail =>
        this.trailLogsAllS3Objects(detail, check.readWriteTypes, allBucketsValues)
      );
      if (covered) continue;

      // Prowler only fails this check when the account actually has S3 buckets
      if (hasBuckets === null) hasBuckets = await this.accountHasS3Buckets();
      if (!hasBuckets) continue;

      findings.push(this.emit(
        check.checkId,
        { region: this.client.getRegion(), trailCount: details.length },
        {
          message: `No CloudTrail trail has a data event selector recording S3 object-level ${check.label} operations for all buckets`,
          remediation: `Add a data event selector for all S3 objects covering ${check.label} events: aws cloudtrail put-event-selectors --trail-name <trail> --event-selectors '[{"ReadWriteType":"${check.readWriteTypes[0]}","DataResources":[{"Type":"AWS::S3::Object","Values":["arn:${partition}:s3"]}]}]'`,
        }
      ));
    }

    return findings;
  }

  private trailLogsAllS3Objects(detail: TrailDetail, readWriteTypes: string[], allBucketsValues: string[]): boolean {
    // Classic selectors: need a matching ReadWriteType plus an all-buckets AWS::S3::Object data resource
    for (const selector of detail.eventSelectors) {
      if (!readWriteTypes.includes(selector.ReadWriteType)) continue;
      for (const resource of selector.DataResources ?? []) {
        if (
          resource.Type === 'AWS::S3::Object' &&
          (resource.Values ?? []).some((value: string) => allBucketsValues.includes(value))
        ) {
          return true;
        }
      }
    }
    // Advanced selectors: Prowler accepts any selector targeting AWS::S3::Object (no read/write distinction)
    for (const selector of detail.advancedEventSelectors) {
      for (const fieldSelector of selector.FieldSelectors ?? []) {
        if (fieldSelector.Field === 'resources.type' && fieldSelector.Equals?.[0] === 'AWS::S3::Object') {
          return true;
        }
      }
    }
    return false;
  }

  private async accountHasS3Buckets(): Promise<boolean> {
    try {
      const result: any = await retry(async () => {
        return await this.client.s3.send(new ListBucketsCommand({}));
      });
      return (result.Buckets ?? []).length > 0;
    } catch (error) {
      logger.debug('Failed to list S3 buckets for CloudTrail data-event checks', { error: (error as Error).message });
      return false; // unknown bucket inventory -> no account-level FAIL (mirrors Prowler)
    }
  }

  /**
   * cloudtrail_threat_detection_llm_jacking: flag identities whose recent CloudTrail
   * activity spans a high diversity of LLM-related API calls. Uses the 90-day
   * event history (LookupEvents), one page per action name like Prowler, scoped
   * to the audited region.
   */
  private async checkLlmJacking(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const startTime = new Date(Date.now() - LLM_JACKING_WINDOW_MINUTES * 60 * 1000);
    const identityActions = new Map<string, { arn: string; type: string; actions: Set<string> }>();

    for (const eventName of LLM_JACKING_ACTIONS) {
      try {
        const result: any = await retry(async () => {
          return await this.client.cloudtrail.send(new LookupEventsCommand({
            LookupAttributes: [{ AttributeKey: 'EventName', AttributeValue: eventName }],
            StartTime: startTime,
          }));
        });
        for (const event of result.Events ?? []) {
          let eventLog: any;
          try {
            eventLog = JSON.parse(event.CloudTrailEvent ?? '{}');
          } catch {
            continue;
          }
          const identity = eventLog?.userIdentity;
          if (!identity?.arn) continue; // events without an identity ARN come from AWS services
          const key = `${identity.arn}|${identity.type ?? ''}`;
          let entry = identityActions.get(key);
          if (!entry) {
            entry = { arn: identity.arn, type: identity.type ?? 'Unknown', actions: new Set<string>() };
            identityActions.set(key, entry);
          }
          entry.actions.add(eventName);
        }
      } catch (error) {
        logger.debug(`LookupEvents failed for event ${eventName}`, { error: (error as Error).message });
      }
    }

    for (const { arn, type, actions } of identityActions.values()) {
      const score = Math.round((actions.size / LLM_JACKING_ACTIONS.length) * 100) / 100;
      if (actions.size / LLM_JACKING_ACTIONS.length > LLM_JACKING_THRESHOLD) {
        const shortName = arn.split('/').pop() || arn;
        findings.push(this.emit(
          'cloudtrail_threat_detection_llm_jacking',
          {
            identityArn: arn,
            identityType: type,
            actions: [...actions].sort(),
            score,
            windowMinutes: LLM_JACKING_WINDOW_MINUTES,
          },
          {
            message: `Potential LLM Jacking attack detected from AWS ${type} ${shortName}: ${actions.size} distinct LLM-related API actions in the last 24h (score ${score})`,
            remediation: `Rotate or deactivate the credentials of ${shortName} immediately, review Bedrock usage and costs, and restrict bedrock:* actions with least-privilege policies or SCPs`,
          }
        ));
      }
    }

    return findings;
  }
}

export default CloudTrailScanner;
