// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  DescribeTrailsCommand,
  GetEventSelectorsCommand
} from '@aws-sdk/client-cloudtrail';
import {
  DescribeMetricFiltersCommand,
  DescribeLogGroupsCommand,
  DescribeResourcePoliciesCommand,
  FilterLogEventsCommand
} from '@aws-sdk/client-cloudwatch-logs';
import {
  DescribeAlarmsCommand
} from '@aws-sdk/client-cloudwatch';
import { GetRoleCommand } from '@aws-sdk/client-iam';
import {
  DescribeFlowLogsCommand
} from '@aws-sdk/client-ec2';
import {
  ConfigServiceClient,
  DescribeConfigurationRecordersCommand,
  DescribeConfigurationRecorderStatusCommand
} from '@aws-sdk/client-config-service';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

interface CISMonitoringRequirement {
  id: string;
  /** Registry checkId; the registry entry's title matches the old findingTitle byte-for-byte */
  checkId: string;
  findingTitle: string;
  keywords: string[];
}

const CIS_MONITORING_REQUIREMENTS: CISMonitoringRequirement[] = [
  {
    id: 'CIS-4.1',
    checkId: 'cloudwatch_log_metric_filter_unauthorized_api_calls',
    findingTitle: 'Unauthorized API Calls Not Monitored',
    keywords: ['UnauthorizedAccess', 'AccessDenied']
  },
  {
    id: 'CIS-4.2',
    checkId: 'cloudwatch_log_metric_filter_sign_in_without_mfa',
    findingTitle: 'Console Sign-In Without MFA Not Monitored',
    keywords: ['ConsoleLogin', 'MFAUsed']
  },
  {
    id: 'CIS-4.3',
    checkId: 'cloudwatch_log_metric_filter_root_usage',
    findingTitle: 'Root Account Usage Not Monitored',
    keywords: ['Root', 'userIdentity']
  },
  {
    id: 'CIS-4.4',
    checkId: 'cloudwatch_log_metric_filter_policy_changes',
    findingTitle: 'IAM Policy Changes Not Monitored',
    keywords: ['DeleteGroupPolicy', 'PutGroupPolicy', 'CreatePolicy', 'AttachRolePolicy']
  },
  {
    id: 'CIS-4.5',
    checkId: 'cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled',
    findingTitle: 'CloudTrail Config Changes Not Monitored',
    keywords: ['StopLogging', 'DeleteTrail', 'UpdateTrail']
  },
  {
    id: 'CIS-4.6',
    checkId: 'cloudwatch_log_metric_filter_authentication_failures',
    findingTitle: 'Console Authentication Failures Not Monitored',
    keywords: ['ConsoleLogin', 'Failure']
  },
  {
    id: 'CIS-4.7',
    checkId: 'cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk',
    findingTitle: 'CMK Deletion Not Monitored',
    keywords: ['ScheduleKeyDeletion', 'DisableKey']
  },
  {
    id: 'CIS-4.8',
    checkId: 'cloudwatch_log_metric_filter_for_s3_bucket_policy_changes',
    findingTitle: 'S3 Bucket Policy Changes Not Monitored',
    keywords: ['PutBucketPolicy', 'DeleteBucketPolicy']
  },
  {
    id: 'CIS-4.9',
    checkId: 'cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled',
    findingTitle: 'AWS Config Changes Not Monitored',
    keywords: ['StopConfigurationRecorder', 'DeleteConfigurationRecorder']
  },
  {
    id: 'CIS-4.10',
    checkId: 'cloudwatch_log_metric_filter_security_group_changes',
    findingTitle: 'Security Group Changes Not Monitored',
    keywords: ['AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupIngress', 'CreateSecurityGroup', 'DeleteSecurityGroup']
  },
  {
    id: 'CIS-4.11',
    checkId: 'cloudwatch_changes_to_network_acls_alarm_configured',
    findingTitle: 'NACL Changes Not Monitored',
    keywords: ['CreateNetworkAcl', 'DeleteNetworkAcl', 'ReplaceNetworkAcl']
  },
  {
    id: 'CIS-4.12',
    checkId: 'cloudwatch_changes_to_network_gateways_alarm_configured',
    findingTitle: 'Network Gateway Changes Not Monitored',
    keywords: ['CreateCustomerGateway', 'DeleteCustomerGateway', 'AttachInternetGateway', 'CreateInternetGateway']
  },
  {
    id: 'CIS-4.13',
    checkId: 'cloudwatch_changes_to_network_route_tables_alarm_configured',
    findingTitle: 'Route Table Changes Not Monitored',
    keywords: ['CreateRoute', 'DeleteRoute', 'ReplaceRoute', 'CreateRouteTable']
  },
  {
    id: 'CIS-4.14',
    checkId: 'cloudwatch_changes_to_vpcs_alarm_configured',
    findingTitle: 'VPC Changes Not Monitored',
    keywords: ['CreateVpc', 'DeleteVpc', 'ModifyVpcAttribute']
  },
  {
    id: 'CIS-4.15',
    checkId: 'cloudwatch_log_metric_filter_aws_organizations_changes',
    findingTitle: 'AWS Organization Changes Not Monitored',
    keywords: ['CreateAccountResult', 'DescribeOrganization']
  }
];

// Minimum log retention required by cloudwatch_log_group_retention_policy_specific_days_enabled
// (Prowler default: log_group_retention_days = 365)
const LOG_GROUP_RETENTION_MIN_DAYS = 365;

// Bounded analysis mirrors Prowler's max_cloudwatch_log_groups resource limit:
// only the newest log groups get the per-group checks, and an even smaller
// subset gets the (expensive) log event sampling for the secrets check.
const MAX_LOG_GROUPS_TO_ANALYZE = 100;
const MAX_LOG_GROUPS_FOR_SECRETS_SCAN = 30;
// Prowler's events_per_log_group_threshold
const MAX_EVENTS_PER_LOG_GROUP = 1000;

// IAM role whose presence means CloudWatch cross-account sharing is active
const CROSS_ACCOUNT_SHARING_ROLE = 'CloudWatch-CrossAccountSharingRole';

/**
 * Lightweight secret detection for sampled log events. Prowler batches events
 * through its detect-secrets scanner; this is a conservative regex port of the
 * most common credential patterns (same approach as the SageMaker scanner).
 */
const SECRET_PATTERNS: { type: string; regex: RegExp }[] = [
  { type: 'AWS Access Key ID', regex: /\b(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/ },
  { type: 'AWS Secret Access Key', regex: /aws_?secret_?access_?key\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}\b/i },
  { type: 'Private Key', regex: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY/ },
  { type: 'Hardcoded Password', regex: /\b(password|passwd|pwd)\b\s*[=:]\s*['"][^'"]{4,}['"]/i },
  { type: 'Hardcoded Secret or Token', regex: /\b(secret|token|api[_-]?key|auth[_-]?key|access[_-]?token)\b\s*[=:]\s*['"][^'"]{8,}['"]/i },
  { type: 'Credentials in URL', regex: /[a-z][a-z0-9+.-]*:\/\/[^/\s:@'"]+:[^/\s:@'"]+@[^\s'"]+/i },
];

export class CloudWatchScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'CloudWatch');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting CloudWatch security scan...');

      const monitoringFindings = await this.checkCISMonitoring();
      findings.push(...monitoringFindings);

      const flowLogFindings = await this.checkVpcFlowLogs();
      findings.push(...flowLogFindings);

      const s3LoggingFindings = await this.checkS3ObjectLevelLogging();
      findings.push(...s3LoggingFindings);

      const configFindings = await this.checkAWSConfig();
      findings.push(...configFindings);

      const alarmActionFindings = await this.checkAlarmActions();
      findings.push(...alarmActionFindings);

      const crossAccountFindings = await this.checkCrossAccountSharing();
      findings.push(...crossAccountFindings);

      const logGroupFindings = await this.checkLogGroups();
      findings.push(...logGroupFindings);

      logger.info(`CloudWatch scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('CloudWatch scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async checkCISMonitoring(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      // Step 1: Get all CloudTrail trails with CloudWatch Logs configured
      const trailsResult = await retry(async () => {
        const cmd = new DescribeTrailsCommand({ includeShadowTrails: true });
        return await this.client.cloudtrail.send(cmd);
      });

      const trails = trailsResult.trailList || [];
      const logGroupArns = trails
        .map(t => t.CloudWatchLogsLogGroupArn)
        .filter((arn): arn is string => !!arn);

      if (logGroupArns.length === 0) {
        findings.push(this.emit(
          'cloudwatch_cloudtrail_log_group_not_configured',
          { trailCount: trails.length, logGroupChecked: 'none', reason: 'no_log_group' },
          {
            message: 'No CloudTrail trails are configured to send logs to CloudWatch Logs. CIS monitoring requirements (4.1-4.15) cannot be verified.',
          }
        ));
        return findings;
      }

      // Step 2: For each log group, fetch all metric filters
      const allMetricFilters: any[] = [];
      for (const logGroupArn of logGroupArns) {
        const logGroupName = this.extractLogGroupName(logGroupArn);
        if (!logGroupName) continue;

        try {
          const filters = await retry(async () => {
            const cmd = new DescribeMetricFiltersCommand({ logGroupName });
            return await this.client.logs.send(cmd);
          });
          allMetricFilters.push(...(filters.metricFilters || []));
        } catch (error) {
          logger.warn(`Failed to get metric filters for log group ${logGroupName}`, {
            error: (error as Error).message
          });
        }
      }

      const logGroupArn = logGroupArns[0];

      // Step 3: Check each CIS requirement
      for (const requirement of CIS_MONITORING_REQUIREMENTS) {
        try {
          const matchingFilter = allMetricFilters.find(filter => {
            const pattern: string = (filter.filterPattern || '').toLowerCase();
            return requirement.keywords.every(kw => pattern.includes(kw.toLowerCase()));
          });

          if (!matchingFilter) {
            findings.push(this.emit(
              requirement.checkId,
              {
                requirementId: requirement.id,
                logGroupChecked: logGroupArn,
                reason: 'no_filter'
              },
              {
                message: `No CloudWatch Logs metric filter was found matching the pattern required for ${requirement.id}.`,
              }
            ));
            continue;
          }

          // Step 4: Check if a CloudWatch alarm exists for the matching metric
          const metricName: string | undefined = matchingFilter.metricTransformations?.[0]?.metricName;
          if (!metricName) {
            findings.push(this.emit(
              requirement.checkId,
              {
                requirementId: requirement.id,
                logGroupChecked: logGroupArn,
                reason: 'no_alarm'
              },
              {
                message: `A metric filter was found for ${requirement.id} but it has no metric transformation defined.`,
              }
            ));
            continue;
          }

          const alarmsResult = await retry(async () => {
            const cmd = new DescribeAlarmsCommand({});
            return await this.client.cloudwatch.send(cmd);
          });

          const alarms = (alarmsResult.MetricAlarms ?? []).filter(a => a.MetricName === metricName);
          if (alarms.length === 0) {
            findings.push(this.emit(
              requirement.checkId,
              {
                requirementId: requirement.id,
                logGroupChecked: logGroupArn,
                reason: 'no_alarm'
              },
              {
                message: `A metric filter exists for ${requirement.id} (metric: "${metricName}") but no CloudWatch alarm is configured for it.`,
              }
            ));
          }
        } catch (error) {
          logger.warn(`Failed to check CIS requirement ${requirement.id}`, {
            error: (error as Error).message
          });
        }
      }
    } catch (error) {
      logger.error('Failed to check CIS monitoring requirements', { error: (error as Error).message });
    }

    return findings;
  }

  private async checkVpcFlowLogs(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new DescribeFlowLogsCommand({});
        return await this.client.ec2.send(cmd);
      });

      const flowLogs = result.FlowLogs || [];
      const vpcFlowLogs = flowLogs.filter(fl => fl.ResourceId?.startsWith('vpc-'));
      const vpcIds = new Set(vpcFlowLogs.map(fl => fl.ResourceId).filter(Boolean));

      if (vpcIds.size === 0) {
        findings.push(this.emit(
          'vpc_flow_logs_enabled',
          { vpcCount: 0, flowLogCount: flowLogs.length },
          {
            message: 'No VPCs have VPC Flow Logs enabled. Network traffic information will not be captured for security analysis.',
          }
        ));
      }
    } catch (error) {
      logger.error('Failed to check VPC Flow Logs', { error: (error as Error).message });
    }

    return findings;
  }

  private async checkS3ObjectLevelLogging(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const trailsResult = await retry(async () => {
        const cmd = new DescribeTrailsCommand({ includeShadowTrails: true });
        return await this.client.cloudtrail.send(cmd);
      });

      const trails = trailsResult.trailList || [];
      let writeLogging = false;
      let readLogging = false;

      for (const trail of trails) {
        const trailName = trail.Name || trail.TrailARN?.split('/')?.pop() || 'Unknown';
        try {
          const selectorsResult = await retry(async () => {
            const cmd = new GetEventSelectorsCommand({ TrailName: trailName });
            return await this.client.cloudtrail.send(cmd);
          });

          for (const selector of selectorsResult.EventSelectors || []) {
            for (const dataResource of selector.DataResources || []) {
              if (dataResource.Type === 'AWS::S3::Object') {
                const values = dataResource.Values || [];
                const coversAll = values.some(v => v === 'arn:aws:s3' || v.endsWith('/*'));
                if (coversAll) {
                  if (selector.ReadWriteType === 'WriteOnly' || selector.ReadWriteType === 'All') {
                    writeLogging = true;
                  }
                  if (selector.ReadWriteType === 'ReadOnly' || selector.ReadWriteType === 'All') {
                    readLogging = true;
                  }
                }
              }
            }
          }
        } catch (error) {
          logger.warn(`Failed to get event selectors for trail ${trailName}`, {
            error: (error as Error).message
          });
        }
      }

      if (!writeLogging || !readLogging) {
        findings.push(this.emit(
          'cloudwatch_s3_object_level_logging_disabled',
          { writeLogging, readLogging },
          {
            message: `S3 object-level logging is not fully enabled in CloudTrail. Write logging: ${writeLogging}, Read logging: ${readLogging}.`,
          }
        ));
      }
    } catch (error) {
      logger.error('Failed to check S3 object-level logging', { error: (error as Error).message });
    }

    return findings;
  }

  private async checkAWSConfig(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const configClient = new ConfigServiceClient({ region: this.client.getRegion() });

      let recorderCount = 0;
      let activeRecorders = 0;

      try {
        const recordersResult = await retry(async () => {
          const cmd = new DescribeConfigurationRecordersCommand({});
          return await configClient.send(cmd);
        });

        const recorders = recordersResult.ConfigurationRecorders || [];
        recorderCount = recorders.length;

        if (recorderCount === 0) {
          findings.push(this.emit(
            'config_recorder_all_regions_enabled',
            { recorderCount: 0, activeRecorders: 0 },
            {
              message: 'No AWS Config configuration recorders were found. AWS resource configurations are not being monitored.',
            }
          ));
          return findings;
        }

        const statusResult = await retry(async () => {
          const cmd = new DescribeConfigurationRecorderStatusCommand({});
          return await configClient.send(cmd);
        });

        for (const status of statusResult.ConfigurationRecordersStatus || []) {
          if (status.recording) {
            activeRecorders++;
          }
        }

        if (activeRecorders === 0) {
          findings.push(this.emit(
            'config_recorder_all_regions_enabled',
            { recorderCount, activeRecorders },
            {
              message: `${recorderCount} AWS Config recorder(s) exist but none are actively recording.`,
            }
          ));
        }
      } catch (error) {
        const errMsg = (error as Error).message || '';
        if (errMsg.toLowerCase().includes('accessdenied') || errMsg.toLowerCase().includes('access denied')) {
          findings.push(this.emit(
            'config_recorder_all_regions_enabled',
            { error: 'permission_denied' },
            {
              message: 'Unable to check AWS Config status due to insufficient permissions.',
            }
          ));
        } else {
          throw error;
        }
      }
    } catch (error) {
      logger.error('Failed to check AWS Config', { error: (error as Error).message });
    }

    return findings;
  }

  // cloudwatch_alarm_actions_alarm_state_configured / cloudwatch_alarm_actions_enabled
  private async checkAlarmActions(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const alarms: any[] = [];
    try {
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.client.cloudwatch.send(new DescribeAlarmsCommand({ NextToken: nextToken }));
        });
        alarms.push(...(result.MetricAlarms ?? []));
        nextToken = result.NextToken;
      } while (nextToken);
    } catch (error) {
      logger.error('Failed to describe CloudWatch alarms', { error: (error as Error).message });
      return findings;
    }

    for (const alarm of alarms) {
      const name: string = alarm.AlarmName ?? 'Unknown';

      if ((alarm.AlarmActions ?? []).length === 0) {
        findings.push(this.emit(
          'cloudwatch_alarm_actions_alarm_state_configured',
          { alarmName: name, alarmArn: alarm.AlarmArn, metricName: alarm.MetricName ?? null, namespace: alarm.Namespace ?? null },
          {
            message: `CloudWatch metric alarm "${name}" has no actions configured for the ALARM state, so threshold breaches trigger no notification or automated response.`,
            remediation: `Add at least one ALARM-state action (e.g. an SNS topic) to alarm "${name}": aws cloudwatch put-metric-alarm --alarm-name ${name} ... --alarm-actions <action-arn>`,
          }
        ));
      }

      if (!alarm.ActionsEnabled) {
        findings.push(this.emit(
          'cloudwatch_alarm_actions_enabled',
          { alarmName: name, alarmArn: alarm.AlarmArn, actionsEnabled: false },
          {
            message: `CloudWatch metric alarm "${name}" has its actions disabled, so state changes will not notify or remediate.`,
            remediation: `Re-enable actions on alarm "${name}": aws cloudwatch enable-alarm-actions --alarm-names ${name}`,
          }
        ));
      }
    }

    return findings;
  }

  // cloudwatch_cross_account_sharing_disabled: the CloudWatch-CrossAccountSharingRole
  // IAM role existing means cross-account sharing of metrics/dashboards is active.
  private async checkCrossAccountSharing(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result: any = await retry(async () => {
        try {
          return await this.client.iam.send(new GetRoleCommand({ RoleName: CROSS_ACCOUNT_SHARING_ROLE }));
        } catch (error) {
          if ((error as any)?.name === 'NoSuchEntityException') return null;
          throw error;
        }
      });

      if (result?.Role) {
        findings.push(this.emit(
          'cloudwatch_cross_account_sharing_disabled',
          { roleName: CROSS_ACCOUNT_SHARING_ROLE, roleArn: result.Role.Arn },
          {
            message: `CloudWatch cross-account sharing is enabled: the IAM role "${CROSS_ACCOUNT_SHARING_ROLE}" exists, allowing other AWS accounts to view metrics, dashboards and alarms in this account.`,
            remediation: `If cross-account sharing is not required, delete the role (aws cloudformation delete-stack --stack-name ${CROSS_ACCOUNT_SHARING_ROLE} if stack-managed); otherwise restrict its trust policy to specific trusted accounts.`,
          }
        ));
      }
    } catch (error) {
      logger.debug('Failed to check CloudWatch cross-account sharing role', { error: (error as Error).message });
    }

    return findings;
  }

  // cloudwatch_log_group_kms_encryption_enabled /
  // cloudwatch_log_group_retention_policy_specific_days_enabled /
  // cloudwatch_log_group_not_publicly_accessible /
  // cloudwatch_log_group_no_secrets_in_logs
  private async checkLogGroups(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const logGroups: any[] = [];
    try {
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.client.logs.send(new DescribeLogGroupsCommand({ nextToken }));
        });
        logGroups.push(...(result.logGroups ?? []));
        nextToken = result.nextToken;
      } while (nextToken);
    } catch (error) {
      logger.error('Failed to describe CloudWatch log groups', { error: (error as Error).message });
      return findings;
    }

    // Mirror Prowler's bounded selection: analyze only the newest log groups.
    const selected = [...logGroups]
      .sort((a, b) => (b.creationTime ?? 0) - (a.creationTime ?? 0))
      .slice(0, MAX_LOG_GROUPS_TO_ANALYZE);
    logger.info(`CloudWatch Logs: analyzing ${selected.length} of ${logGroups.length} log group(s)`);

    for (const logGroup of selected) {
      const name: string = logGroup.logGroupName ?? 'Unknown';

      if (!logGroup.kmsKeyId) {
        findings.push(this.emit(
          'cloudwatch_log_group_kms_encryption_enabled',
          { logGroup: name, arn: logGroup.arn, kmsKeyId: null },
          {
            message: `CloudWatch log group "${name}" is not encrypted with a customer-managed KMS key.`,
            remediation: `Associate a KMS key with log group "${name}": aws logs associate-kms-key --log-group-name ${name} --kms-key-id <key-arn>`,
          }
        ));
      }

      // No retentionInDays means the log group never expires, which passes.
      const retentionDays: number | undefined = logGroup.retentionInDays;
      if (retentionDays && retentionDays < LOG_GROUP_RETENTION_MIN_DAYS) {
        findings.push(this.emit(
          'cloudwatch_log_group_retention_policy_specific_days_enabled',
          { logGroup: name, arn: logGroup.arn, retentionDays, requiredDays: LOG_GROUP_RETENTION_MIN_DAYS },
          {
            message: `CloudWatch log group "${name}" retains logs for only ${retentionDays} days, below the ${LOG_GROUP_RETENTION_MIN_DAYS}-day minimum.`,
            remediation: `Raise the retention on log group "${name}": aws logs put-retention-policy --log-group-name ${name} --retention-in-days ${LOG_GROUP_RETENTION_MIN_DAYS}`,
          }
        ));
      }
    }

    findings.push(...(await this.checkLogGroupPublicAccess(selected)));
    findings.push(...(await this.checkLogGroupSecrets(selected.slice(0, MAX_LOG_GROUPS_FOR_SECRETS_SCAN))));

    return findings;
  }

  // cloudwatch_log_group_not_publicly_accessible: a CloudWatch Logs resource
  // policy with a wildcard principal exposes the log groups its statements cover.
  private async checkLogGroupPublicAccess(logGroups: any[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    if (logGroups.length === 0) return findings;

    const policies: any[] = [];
    try {
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.client.logs.send(new DescribeResourcePoliciesCommand({ nextToken }));
        });
        policies.push(...(result.resourcePolicies ?? []));
        nextToken = result.nextToken;
      } while (nextToken);
    } catch (error) {
      logger.debug('Failed to describe CloudWatch Logs resource policies', { error: (error as Error).message });
      return findings;
    }

    // Collect resources granted to a public principal by any resource policy.
    const publicResources: { resource: string; policyName: string }[] = [];
    for (const policy of policies) {
      let doc: any;
      try {
        doc = JSON.parse(policy.policyDocument ?? '{}');
      } catch {
        continue;
      }
      const statements: any[] = Array.isArray(doc.Statement) ? doc.Statement : (doc.Statement ? [doc.Statement] : []);
      for (const stmt of statements) {
        // Conservative public test: Allow + wildcard principal + no Condition.
        if (stmt?.Effect !== 'Allow' || stmt.Condition) continue;
        if (!this.isPrincipalPublic(stmt.Principal)) continue;
        const resources: any[] = Array.isArray(stmt.Resource) ? stmt.Resource : (stmt.Resource ? [stmt.Resource] : []);
        for (const resource of resources) {
          publicResources.push({ resource: String(resource), policyName: policy.policyName ?? 'Unknown' });
        }
      }
    }
    if (publicResources.length === 0) return findings;

    for (const logGroup of logGroups) {
      const name: string = logGroup.logGroupName ?? 'Unknown';
      // DescribeLogGroups ARNs end in ":*"; strip it before substring matching.
      const baseArn: string = String(logGroup.arn ?? '').replace(/:\*$/, '');
      const match = publicResources.find(pr => pr.resource === '*' || (baseArn && pr.resource.includes(baseArn)));
      if (match) {
        findings.push(this.emit(
          'cloudwatch_log_group_not_publicly_accessible',
          { logGroup: name, arn: logGroup.arn, policyName: match.policyName, matchedResource: match.resource },
          {
            message: `CloudWatch log group "${name}" is publicly accessible: resource policy "${match.policyName}" grants access to any principal ("*") on resource "${match.resource}".`,
            remediation: `Delete or scope down the public resource policy: aws logs delete-resource-policy --policy-name ${match.policyName}, or replace Principal "*" with specific AWS account principals.`,
          }
        ));
      }
    }

    return findings;
  }

  // cloudwatch_log_group_no_secrets_in_logs: sample recent log events per log
  // group (bounded, like Prowler's 1000-events-per-group threshold) and scan
  // them for credential patterns. Only secret types and stream names are
  // reported — never the matched values.
  private async checkLogGroupSecrets(logGroups: any[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    for (const logGroup of logGroups) {
      const name: string = logGroup.logGroupName ?? '';
      if (!name) continue;

      let events: any[] = [];
      try {
        const result: any = await retry(async () => {
          return await this.client.logs.send(new FilterLogEventsCommand({ logGroupName: name, limit: MAX_EVENTS_PER_LOG_GROUP }));
        });
        events = result.events ?? [];
      } catch (error) {
        logger.debug(`Failed to sample log events for log group ${name}`, { error: (error as Error).message });
        continue;
      }
      if (events.length === 0) continue;

      const hits: { logStream: string; type: string }[] = [];
      const seen = new Set<string>();
      for (const event of events) {
        const message = String(event.message ?? '');
        for (const pattern of SECRET_PATTERNS) {
          if (!pattern.regex.test(message)) continue;
          const logStream: string = event.logStreamName ?? 'unknown';
          const key = `${logStream}::${pattern.type}`;
          if (!seen.has(key)) {
            seen.add(key);
            hits.push({ logStream, type: pattern.type });
          }
        }
      }

      if (hits.length > 0) {
        const detail = hits.slice(0, 10).map(h => `${h.type} in log stream "${h.logStream}"`).join('; ');
        findings.push(this.emit(
          'cloudwatch_log_group_no_secrets_in_logs',
          {
            logGroup: name,
            arn: logGroup.arn,
            sampledEvents: events.length,
            secretTypes: [...new Set(hits.map(h => h.type))],
            matches: hits.slice(0, 10),
          },
          {
            message: `Potential secrets found in log group "${name}" (sampled ${events.length} recent events): ${detail}.`,
            remediation: `Stop logging secrets from the producing application, rotate any exposed credentials, and apply a CloudWatch Logs data protection policy to log group "${name}" to mask credentials at egress.`,
          }
        ));
      }
    }

    return findings;
  }

  private isPrincipalPublic(principal: any): boolean {
    if (principal === '*') return true;
    if (!principal || typeof principal !== 'object') return false;
    const aws = principal.AWS;
    if (aws === '*') return true;
    if (Array.isArray(aws) && aws.includes('*')) return true;
    return false;
  }

  private extractLogGroupName(logGroupArn: string): string | null {
    // ARN format: arn:aws:logs:region:account-id:log-group:log-group-name:*
    const parts = logGroupArn.split(':');
    const logGroupIndex = parts.indexOf('log-group');
    if (logGroupIndex !== -1 && parts[logGroupIndex + 1]) {
      return parts[logGroupIndex + 1];
    }
    return null;
  }
}

export default CloudWatchScanner;
