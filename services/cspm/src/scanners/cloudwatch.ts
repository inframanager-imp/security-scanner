import {
  DescribeTrailsCommand,
  GetEventSelectorsCommand
} from '@aws-sdk/client-cloudtrail';
import {
  DescribeMetricFiltersCommand
} from '@aws-sdk/client-cloudwatch-logs';
import {
  DescribeAlarmsCommand
} from '@aws-sdk/client-cloudwatch';
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
