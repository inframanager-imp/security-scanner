// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  ConfigServiceClient,
  DescribeConfigurationRecordersCommand,
  DescribeConfigurationAggregatorsCommand,
} from '@aws-sdk/client-config-service';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class ConfigScanner extends BaseScanner {
  private config: ConfigServiceClient;

  constructor(client: AWSClient) {
    super(client, 'Config');
    this.config = new ConfigServiceClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting AWS Config security scan...');

      findings.push(...(await this.checkRecorderRole()));
      findings.push(...(await this.checkOrgAggregator()));

      logger.info(`Config scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Config scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  // config_recorder_using_aws_service_role: recorders should use the
  // service-linked role, not a custom role with broader permissions.
  private async checkRecorderRole(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const result: any = await retry(async () => {
        return await this.config.send(new DescribeConfigurationRecordersCommand({}));
      });
      for (const recorder of result.ConfigurationRecorders ?? []) {
        const roleArn: string = recorder.roleARN ?? '';
        if (!roleArn.includes(':role/aws-service-role/config.amazonaws.com/')) {
          findings.push(this.emit(
            'config_recorder_using_aws_service_role',
            { recorder: recorder.name, roleArn },
            {
              message: `AWS Config recorder "${recorder.name}" uses custom role "${roleArn}" instead of the Config service-linked role`,
              remediation: `Update recorder "${recorder.name}" to use the AWSServiceRoleForConfig service-linked role so its permissions stay scoped and AWS-managed`,
            }
          ));
        }
      }
    } catch (error) {
      logger.debug('Failed to describe Config recorders', { error: (error as Error).message });
    }
    return findings;
  }

  // config_delegated_admin_and_org_aggregator_all_regions: an organization
  // aggregator covering every region should exist for org-wide visibility.
  private async checkOrgAggregator(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const result: any = await retry(async () => {
        return await this.config.send(new DescribeConfigurationAggregatorsCommand({}));
      });
      const aggregators: any[] = result.ConfigurationAggregators ?? [];
      const orgAllRegions = aggregators.find(
        (a) => a.OrganizationAggregationSource?.AllAwsRegions === true
      );
      if (!orgAllRegions) {
        const partial = aggregators.find((a) => a.OrganizationAggregationSource);
        findings.push(this.emit(
          'config_delegated_admin_and_org_aggregator_all_regions',
          {
            aggregators: aggregators.map((a) => a.ConfigurationAggregatorName),
            hasOrgAggregator: Boolean(partial),
          },
          {
            message: partial
              ? `AWS Config organization aggregator "${partial.ConfigurationAggregatorName}" does not cover all regions`
              : 'No AWS Config organization aggregator covering all regions was found in this account',
            remediation: 'Create (or update) an AWS Config organization aggregator with AllAwsRegions enabled, from a delegated administrator account',
          }
        ));
      }
    } catch (error) {
      logger.debug('Failed to describe Config aggregators', { error: (error as Error).message });
    }
    return findings;
  }
}

export default ConfigScanner;
