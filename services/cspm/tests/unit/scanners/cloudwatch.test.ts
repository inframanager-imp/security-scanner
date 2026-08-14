import { describe, it, expect, beforeEach, afterEach, afterAll } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetEventSelectorsCommand,
} from '@aws-sdk/client-cloudtrail';
import {
  CloudWatchLogsClient,
  DescribeMetricFiltersCommand,
  DescribeLogGroupsCommand,
  DescribeResourcePoliciesCommand,
  FilterLogEventsCommand,
} from '@aws-sdk/client-cloudwatch-logs';
import { CloudWatchClient, DescribeAlarmsCommand } from '@aws-sdk/client-cloudwatch';
import { IAMClient, GetRoleCommand } from '@aws-sdk/client-iam';
import { EC2Client, DescribeFlowLogsCommand } from '@aws-sdk/client-ec2';
import {
  ConfigServiceClient,
  DescribeConfigurationRecordersCommand,
  DescribeConfigurationRecorderStatusCommand,
} from '@aws-sdk/client-config-service';
import CloudWatchScanner from '../../../src/scanners/cloudwatch';

// CloudWatchScanner reaches its AWS clients via pre-instantiated properties on
// AWSClient (this.client.cloudtrail / .logs / .cloudwatch / .ec2 / .iam) rather
// than getClientConfig(), and it also builds its own ConfigServiceClient
// internally from client.getRegion(). aws-sdk-client-mock's mockClient()
// intercepts calls at the SDK-class level (via the prototype), so as long as
// our stand-in AWSClient's properties are real instances of these classes
// constructed with any config, calls through them are captured regardless of
// which "client" object holds the reference — including the scanner's own
// internally-constructed ConfigServiceClient.
const cloudtrailMock = mockClient(CloudTrailClient);
const logsMock = mockClient(CloudWatchLogsClient);
const cloudwatchMock = mockClient(CloudWatchClient);
const iamMock = mockClient(IAMClient);
const ec2Mock = mockClient(EC2Client);
const configMock = mockClient(ConfigServiceClient);

function makeMockAWSClient() {
  return {
    getClientConfig: () => ({ region: 'us-east-1', credentials: {} }),
    getRegion: () => 'us-east-1',
    cloudtrail: new CloudTrailClient({ region: 'us-east-1' }),
    logs: new CloudWatchLogsClient({ region: 'us-east-1' }),
    cloudwatch: new CloudWatchClient({ region: 'us-east-1' }),
    iam: new IAMClient({ region: 'us-east-1' }),
    ec2: new EC2Client({ region: 'us-east-1' }),
  } as any;
}

// Baseline "everything is clean" stubs so tests that only care about one
// sub-check don't have to also silence every other sub-check's finding.
// Individual tests override whichever commands are relevant to them.
function primeCleanDefaults() {
  cloudtrailMock.on(DescribeTrailsCommand).resolves({
    trailList: [{ Name: 'trail-1', TrailARN: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/trail-1', CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:123456789012:log-group:trail-log-group:*' }],
  });
  cloudtrailMock.on(GetEventSelectorsCommand).resolves({
    EventSelectors: [
      {
        ReadWriteType: 'All',
        DataResources: [{ Type: 'AWS::S3::Object', Values: ['arn:aws:s3'] }],
      },
    ],
  });
  logsMock.on(DescribeMetricFiltersCommand).resolves({
    metricFilters: CIS_ALL_PATTERNS_FILTERS,
  });
  cloudwatchMock.on(DescribeAlarmsCommand).resolves({
    MetricAlarms: CIS_ALL_PATTERNS_FILTERS.map((f, i) => ({
      AlarmName: `alarm-${i}`,
      MetricName: f.metricTransformations[0].metricName,
      AlarmActions: ['arn:aws:sns:us-east-1:123456789012:topic'],
      ActionsEnabled: true,
    })),
  });
  ec2Mock.on(DescribeFlowLogsCommand).resolves({
    FlowLogs: [{ ResourceId: 'vpc-1234' }],
  });
  configMock.on(DescribeConfigurationRecordersCommand).resolves({
    ConfigurationRecorders: [{ name: 'default' }],
  });
  configMock.on(DescribeConfigurationRecorderStatusCommand).resolves({
    ConfigurationRecordersStatus: [{ name: 'default', recording: true }],
  });
  iamMock.on(GetRoleCommand).rejects(Object.assign(new Error('not found'), { name: 'NoSuchEntityException' }));
  logsMock.on(DescribeLogGroupsCommand).resolves({ logGroups: [] });
  logsMock.on(DescribeResourcePoliciesCommand).resolves({ resourcePolicies: [] });
  logsMock.on(FilterLogEventsCommand).resolves({ events: [] });
}

// One metric filter + matching alarm per CIS_MONITORING_REQUIREMENTS keyword
// set, built directly from the keyword lists in the scanner's own CIS table,
// so `primeCleanDefaults()` satisfies every CIS-4.x requirement at once.
const CIS_ALL_PATTERNS_FILTERS = [
  { filterPattern: '{ $.errorCode = "*UnauthorizedAccess*" || $.errorCode = "AccessDenied*" }', metricTransformations: [{ metricName: 'UnauthorizedAPICalls' }] },
  { filterPattern: '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }', metricTransformations: [{ metricName: 'ConsoleSignInWithoutMFA' }] },
  { filterPattern: '{ $.userIdentity.type = "Root" }', metricTransformations: [{ metricName: 'RootUsage' }] },
  { filterPattern: '{ ($.eventName=DeleteGroupPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=CreatePolicy) || ($.eventName=AttachRolePolicy) }', metricTransformations: [{ metricName: 'IAMPolicyChanges' }] },
  { filterPattern: '{ ($.eventName = StopLogging) || ($.eventName = DeleteTrail) || ($.eventName = UpdateTrail) }', metricTransformations: [{ metricName: 'CloudTrailChanges' }] },
  { filterPattern: '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }', metricTransformations: [{ metricName: 'AuthFailures' }] },
  { filterPattern: '{ ($.eventName=ScheduleKeyDeletion) || ($.eventName=DisableKey) }', metricTransformations: [{ metricName: 'CMKDeletion' }] },
  { filterPattern: '{ ($.eventName = PutBucketPolicy) || ($.eventName = DeleteBucketPolicy) }', metricTransformations: [{ metricName: 'S3PolicyChanges' }] },
  { filterPattern: '{ ($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteConfigurationRecorder) }', metricTransformations: [{ metricName: 'ConfigChanges' }] },
  { filterPattern: '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }', metricTransformations: [{ metricName: 'SGChanges' }] },
  { filterPattern: '{ ($.eventName = CreateNetworkAcl) || ($.eventName = DeleteNetworkAcl) || ($.eventName = ReplaceNetworkAcl) }', metricTransformations: [{ metricName: 'NACLChanges' }] },
  { filterPattern: '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) }', metricTransformations: [{ metricName: 'GatewayChanges' }] },
  { filterPattern: '{ ($.eventName = CreateRoute) || ($.eventName = DeleteRoute) || ($.eventName = ReplaceRoute) || ($.eventName = CreateRouteTable) }', metricTransformations: [{ metricName: 'RouteTableChanges' }] },
  { filterPattern: '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) }', metricTransformations: [{ metricName: 'VPCChanges' }] },
  { filterPattern: '{ ($.eventName = CreateAccountResult) || ($.eventName = DescribeOrganization) }', metricTransformations: [{ metricName: 'OrgChanges' }] },
];

describe('CloudWatchScanner', () => {
  beforeEach(() => {
    cloudtrailMock.reset();
    logsMock.reset();
    cloudwatchMock.reset();
    iamMock.reset();
    ec2Mock.reset();
    configMock.reset();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  afterAll(() => {
    cloudtrailMock.restore();
    logsMock.restore();
    cloudwatchMock.restore();
    iamMock.restore();
    ec2Mock.restore();
    configMock.restore();
  });

  describe('checkAlarmActions (cloudwatch_alarm_actions_alarm_state_configured / cloudwatch_alarm_actions_enabled)', () => {
    it('emits findings for an alarm with no AlarmActions and for an alarm with ActionsEnabled=false', async () => {
      primeCleanDefaults();
      cloudwatchMock.reset();
      cloudwatchMock.on(DescribeAlarmsCommand).resolves({
        MetricAlarms: [
          {
            AlarmName: 'no-actions-alarm',
            AlarmArn: 'arn:aws:cloudwatch:us-east-1:123456789012:alarm:no-actions-alarm',
            MetricName: 'CPUUtilization',
            Namespace: 'AWS/EC2',
            AlarmActions: [],
            ActionsEnabled: true,
          },
          {
            AlarmName: 'disabled-actions-alarm',
            AlarmArn: 'arn:aws:cloudwatch:us-east-1:123456789012:alarm:disabled-actions-alarm',
            MetricName: 'DiskUsage',
            Namespace: 'AWS/EC2',
            AlarmActions: ['arn:aws:sns:us-east-1:123456789012:topic'],
            ActionsEnabled: false,
          },
        ],
      });

      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const noActionsFinding = findings.find(
        (f) => f.checkId === 'cloudwatch_alarm_actions_alarm_state_configured'
      );
      expect(noActionsFinding).toBeDefined();
      expect(noActionsFinding?.service).toBe('CloudWatch');
      expect(noActionsFinding?.evidence.alarmName).toBe('no-actions-alarm');

      const disabledActionsFinding = findings.find(
        (f) => f.checkId === 'cloudwatch_alarm_actions_enabled'
      );
      expect(disabledActionsFinding).toBeDefined();
      expect(disabledActionsFinding?.service).toBe('CloudWatch');
      expect(disabledActionsFinding?.evidence.alarmName).toBe('disabled-actions-alarm');
    });

    it('emits no alarm-action findings when every alarm has actions configured and enabled', async () => {
      primeCleanDefaults();
      cloudwatchMock.reset();
      cloudwatchMock.on(DescribeAlarmsCommand).resolves({
        MetricAlarms: [
          {
            AlarmName: 'healthy-alarm',
            AlarmArn: 'arn:aws:cloudwatch:us-east-1:123456789012:alarm:healthy-alarm',
            MetricName: 'CPUUtilization',
            AlarmActions: ['arn:aws:sns:us-east-1:123456789012:topic'],
            ActionsEnabled: true,
          },
        ],
      });

      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findings.find((f) => f.checkId === 'cloudwatch_alarm_actions_alarm_state_configured')).toBeUndefined();
      expect(findings.find((f) => f.checkId === 'cloudwatch_alarm_actions_enabled')).toBeUndefined();
    });

    it('paginates DescribeAlarmsCommand across two pages and processes alarms from both', async () => {
      primeCleanDefaults();
      cloudwatchMock.reset();
      // No metric filter matches any CIS requirement's keywords, so
      // checkCISMonitoring's own (unpaginated) DescribeAlarmsCommand call
      // never triggers — every DescribeAlarmsCommand call in this test comes
      // from checkAlarmActions, keeping the two-page mock sequence exclusive
      // to the pagination loop under test.
      logsMock.reset();
      logsMock.on(DescribeMetricFiltersCommand).resolves({ metricFilters: [] });
      logsMock.on(DescribeLogGroupsCommand).resolves({ logGroups: [] });
      logsMock.on(DescribeResourcePoliciesCommand).resolves({ resourcePolicies: [] });
      logsMock.on(FilterLogEventsCommand).resolves({ events: [] });
      cloudwatchMock
        .on(DescribeAlarmsCommand)
        .resolvesOnce({
          MetricAlarms: [
            {
              AlarmName: 'page-1-alarm',
              AlarmArn: 'arn:aws:cloudwatch:us-east-1:123456789012:alarm:page-1-alarm',
              MetricName: 'Metric1',
              AlarmActions: [],
              ActionsEnabled: true,
            },
          ],
          NextToken: 'token-2',
        })
        .resolvesOnce({
          MetricAlarms: [
            {
              AlarmName: 'page-2-alarm',
              AlarmArn: 'arn:aws:cloudwatch:us-east-1:123456789012:alarm:page-2-alarm',
              MetricName: 'Metric2',
              AlarmActions: [],
              ActionsEnabled: true,
            },
          ],
        });

      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const noActionFindings = findings.filter(
        (f) => f.checkId === 'cloudwatch_alarm_actions_alarm_state_configured'
      );
      const names = noActionFindings.map((f) => f.evidence.alarmName).sort();
      expect(names).toEqual(['page-1-alarm', 'page-2-alarm']);

      expect(cloudwatchMock.commandCalls(DescribeAlarmsCommand).length).toBeGreaterThanOrEqual(2);
    });

    it('does not throw and returns gracefully when DescribeAlarmsCommand rejects', async () => {
      jest.useFakeTimers({ doNotFake: ['nextTick'] });
      primeCleanDefaults();
      cloudwatchMock.reset();
      cloudwatchMock.on(DescribeAlarmsCommand).rejects(new Error('AWS is down'));

      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const scanPromise = scanner.scan();
      // retry() backs off with real setTimeout delays (1s, 2s, ...) between
      // its 3 attempts; advance fake timers so the rejection surfaces quickly.
      await jest.runAllTimersAsync();
      const findings = await scanPromise;

      expect(Array.isArray(findings)).toBe(true);
      expect(findings.find((f) => f.checkId === 'cloudwatch_alarm_actions_alarm_state_configured')).toBeUndefined();
      expect(findings.find((f) => f.checkId === 'cloudwatch_alarm_actions_enabled')).toBeUndefined();
    }, 15000);
  });

  describe('checkVpcFlowLogs (vpc_flow_logs_enabled)', () => {
    it('emits a finding when no VPC has flow logs enabled', async () => {
      primeCleanDefaults();
      ec2Mock.reset();
      ec2Mock.on(DescribeFlowLogsCommand).resolves({ FlowLogs: [] });

      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const flowLogFinding = findings.find((f) => f.checkId === 'vpc_flow_logs_enabled');
      expect(flowLogFinding).toBeDefined();
      expect(flowLogFinding?.service).toBe('CloudWatch');
      expect(flowLogFinding?.evidence.vpcCount).toBe(0);
    });

    it('emits no finding when at least one VPC has flow logs enabled', async () => {
      primeCleanDefaults();
      ec2Mock.reset();
      ec2Mock.on(DescribeFlowLogsCommand).resolves({ FlowLogs: [{ ResourceId: 'vpc-abc123' }] });

      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findings.find((f) => f.checkId === 'vpc_flow_logs_enabled')).toBeUndefined();
    });

    it('does not throw when DescribeFlowLogsCommand rejects', async () => {
      jest.useFakeTimers({ doNotFake: ['nextTick'] });
      primeCleanDefaults();
      ec2Mock.reset();
      ec2Mock.on(DescribeFlowLogsCommand).rejects(new Error('access denied'));

      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const scanPromise = scanner.scan();
      await jest.runAllTimersAsync();
      await expect(scanPromise).resolves.toBeInstanceOf(Array);
    }, 15000);
  });

  describe('checkAWSConfig (config_recorder_all_regions_enabled)', () => {
    it('emits a finding when no configuration recorders exist', async () => {
      primeCleanDefaults();
      configMock.reset();
      configMock.on(DescribeConfigurationRecordersCommand).resolves({ ConfigurationRecorders: [] });

      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const configFinding = findings.find((f) => f.checkId === 'config_recorder_all_regions_enabled');
      expect(configFinding).toBeDefined();
      expect(configFinding?.evidence.recorderCount).toBe(0);
    });

    it('emits a finding when recorders exist but none are actively recording', async () => {
      primeCleanDefaults();
      configMock.reset();
      configMock.on(DescribeConfigurationRecordersCommand).resolves({
        ConfigurationRecorders: [{ name: 'default' }],
      });
      configMock.on(DescribeConfigurationRecorderStatusCommand).resolves({
        ConfigurationRecordersStatus: [{ name: 'default', recording: false }],
      });

      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const configFinding = findings.find((f) => f.checkId === 'config_recorder_all_regions_enabled');
      expect(configFinding).toBeDefined();
      expect(configFinding?.evidence.activeRecorders).toBe(0);
    });

    it('emits no finding when a recorder is actively recording', async () => {
      primeCleanDefaults();
      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findings.find((f) => f.checkId === 'config_recorder_all_regions_enabled')).toBeUndefined();
    });
  });

  describe('checkCrossAccountSharing (cloudwatch_cross_account_sharing_disabled)', () => {
    it('emits a finding when the CloudWatch-CrossAccountSharingRole IAM role exists', async () => {
      primeCleanDefaults();
      iamMock.reset();
      iamMock.on(GetRoleCommand).resolves({
        Role: {
          RoleName: 'CloudWatch-CrossAccountSharingRole',
          Arn: 'arn:aws:iam::123456789012:role/CloudWatch-CrossAccountSharingRole',
        } as any,
      });

      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const crossAccountFinding = findings.find((f) => f.checkId === 'cloudwatch_cross_account_sharing_disabled');
      expect(crossAccountFinding).toBeDefined();
      expect(crossAccountFinding?.service).toBe('CloudWatch');
      expect(crossAccountFinding?.evidence.roleName).toBe('CloudWatch-CrossAccountSharingRole');
    });

    it('emits no finding when the role does not exist (NoSuchEntityException)', async () => {
      primeCleanDefaults();
      // primeCleanDefaults() already rejects GetRoleCommand with NoSuchEntityException
      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findings.find((f) => f.checkId === 'cloudwatch_cross_account_sharing_disabled')).toBeUndefined();
    });
  });

  describe('checkLogGroups (cloudwatch_log_group_kms_encryption_enabled / cloudwatch_log_group_retention_policy_specific_days_enabled)', () => {
    it('emits findings for an unencrypted log group and one with retention below the minimum', async () => {
      primeCleanDefaults();
      logsMock.reset();
      logsMock.on(DescribeMetricFiltersCommand).resolves({ metricFilters: CIS_ALL_PATTERNS_FILTERS });
      logsMock.on(DescribeResourcePoliciesCommand).resolves({ resourcePolicies: [] });
      logsMock.on(FilterLogEventsCommand).resolves({ events: [] });
      logsMock.on(DescribeLogGroupsCommand).resolves({
        logGroups: [
          {
            logGroupName: '/aws/lambda/unencrypted-fn',
            arn: 'arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/unencrypted-fn:*',
            kmsKeyId: undefined,
            retentionInDays: 400,
            creationTime: 2000,
          },
          {
            logGroupName: '/aws/lambda/short-retention-fn',
            arn: 'arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/short-retention-fn:*',
            kmsKeyId: 'arn:aws:kms:us-east-1:123456789012:key/abc',
            retentionInDays: 7,
            creationTime: 1000,
          },
        ],
      });

      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const kmsFinding = findings.find((f) => f.checkId === 'cloudwatch_log_group_kms_encryption_enabled');
      expect(kmsFinding).toBeDefined();
      expect(kmsFinding?.evidence.logGroup).toBe('/aws/lambda/unencrypted-fn');

      const retentionFinding = findings.find(
        (f) => f.checkId === 'cloudwatch_log_group_retention_policy_specific_days_enabled'
      );
      expect(retentionFinding).toBeDefined();
      expect(retentionFinding?.evidence.logGroup).toBe('/aws/lambda/short-retention-fn');
      expect(retentionFinding?.evidence.retentionDays).toBe(7);
    });

    it('emits no log-group findings when no log groups exist', async () => {
      primeCleanDefaults();
      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      expect(findings.find((f) => f.checkId === 'cloudwatch_log_group_kms_encryption_enabled')).toBeUndefined();
      expect(findings.find((f) => f.checkId === 'cloudwatch_log_group_retention_policy_specific_days_enabled')).toBeUndefined();
    });

    it('paginates DescribeLogGroupsCommand across two pages and analyzes log groups from both', async () => {
      primeCleanDefaults();
      logsMock.reset();
      logsMock.on(DescribeMetricFiltersCommand).resolves({ metricFilters: CIS_ALL_PATTERNS_FILTERS });
      logsMock.on(DescribeResourcePoliciesCommand).resolves({ resourcePolicies: [] });
      logsMock.on(FilterLogEventsCommand).resolves({ events: [] });
      logsMock
        .on(DescribeLogGroupsCommand)
        .resolvesOnce({
          logGroups: [
            { logGroupName: '/page/one', arn: 'arn:one:*', kmsKeyId: undefined, creationTime: 5000 },
          ],
          nextToken: 'next-page',
        })
        .resolvesOnce({
          logGroups: [
            { logGroupName: '/page/two', arn: 'arn:two:*', kmsKeyId: undefined, creationTime: 4000 },
          ],
        });

      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const kmsFindings = findings.filter((f) => f.checkId === 'cloudwatch_log_group_kms_encryption_enabled');
      const names = kmsFindings.map((f) => f.evidence.logGroup).sort();
      expect(names).toEqual(['/page/one', '/page/two']);
      expect(logsMock.commandCalls(DescribeLogGroupsCommand).length).toBeGreaterThanOrEqual(2);
    });

    it('does not throw and returns gracefully when DescribeLogGroupsCommand rejects', async () => {
      jest.useFakeTimers({ doNotFake: ['nextTick'] });
      primeCleanDefaults();
      logsMock.reset();
      logsMock.on(DescribeMetricFiltersCommand).resolves({ metricFilters: [] });
      logsMock.on(DescribeLogGroupsCommand).rejects(new Error('throttled'));

      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const scanPromise = scanner.scan();
      await jest.runAllTimersAsync();
      const findings = await scanPromise;

      expect(Array.isArray(findings)).toBe(true);
      expect(findings.find((f) => f.checkId === 'cloudwatch_log_group_kms_encryption_enabled')).toBeUndefined();
    }, 15000);
  });

  describe('checkCISMonitoring (cloudwatch_cloudtrail_log_group_not_configured)', () => {
    it('emits a finding when no CloudTrail trail has a CloudWatch Logs group configured', async () => {
      primeCleanDefaults();
      cloudtrailMock.reset();
      cloudtrailMock.on(DescribeTrailsCommand).resolves({
        trailList: [{ Name: 'trail-1', TrailARN: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/trail-1' }],
      });

      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const findings = await scanner.scan();

      const noLogGroupFinding = findings.find(
        (f) => f.checkId === 'cloudwatch_cloudtrail_log_group_not_configured'
      );
      expect(noLogGroupFinding).toBeDefined();
      expect(noLogGroupFinding?.service).toBe('CloudWatch');
      expect(noLogGroupFinding?.evidence.reason).toBe('no_log_group');
    });
  });

  describe('overall scan()', () => {
    it('returns an empty array without throwing when every underlying AWS call rejects', async () => {
      jest.useFakeTimers({ doNotFake: ['nextTick'] });
      cloudtrailMock.on(DescribeTrailsCommand).rejects(new Error('boom'));
      logsMock.on(DescribeMetricFiltersCommand).rejects(new Error('boom'));
      logsMock.on(DescribeLogGroupsCommand).rejects(new Error('boom'));
      logsMock.on(DescribeResourcePoliciesCommand).rejects(new Error('boom'));
      logsMock.on(FilterLogEventsCommand).rejects(new Error('boom'));
      cloudwatchMock.on(DescribeAlarmsCommand).rejects(new Error('boom'));
      ec2Mock.on(DescribeFlowLogsCommand).rejects(new Error('boom'));
      configMock.on(DescribeConfigurationRecordersCommand).rejects(new Error('boom'));
      iamMock.on(GetRoleCommand).rejects(new Error('boom'));

      const scanner = new CloudWatchScanner(makeMockAWSClient());
      const scanPromise = scanner.scan();
      await jest.runAllTimersAsync();
      const findings = await scanPromise;

      expect(findings).toEqual([]);
    }, 20000);
  });
});
