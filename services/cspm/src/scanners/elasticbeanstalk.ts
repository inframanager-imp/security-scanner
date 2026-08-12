// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  ElasticBeanstalkClient,
  DescribeEnvironmentsCommand,
  DescribeConfigurationSettingsCommand,
} from '@aws-sdk/client-elastic-beanstalk';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class ElasticBeanstalkScanner extends BaseScanner {
  private elasticbeanstalk: ElasticBeanstalkClient;

  constructor(client: AWSClient) {
    super(client, 'ElasticBeanstalk');
    this.elasticbeanstalk = new ElasticBeanstalkClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting ElasticBeanstalk security scan...');

      const environments = await this.describeEnvironments();
      for (const environment of environments) {
        const envName: string = environment.EnvironmentName ?? environment.EnvironmentId ?? 'unknown';
        logger.debug(`Scanning Elastic Beanstalk environment: ${envName}`);
        try {
          findings.push(...await this.validateEnvironment(environment));
        } catch (error) {
          logger.debug(`Failed to scan Elastic Beanstalk environment ${envName}`, { error: (error as Error).message });
        }
      }

      logger.info(`ElasticBeanstalk scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('ElasticBeanstalk scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async describeEnvironments(): Promise<any[]> {
    const environments: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.elasticbeanstalk.send(new DescribeEnvironmentsCommand({ NextToken: nextToken }));
      });
      environments.push(...(result.Environments ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return environments;
  }

  private async validateEnvironment(environment: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const envName: string = environment.EnvironmentName ?? 'unknown';
    const applicationName: string = environment.ApplicationName ?? '';
    const arn: string = environment.EnvironmentArn ?? '';

    // Defaults mirror Prowler: options absent -> non-compliant values
    let healthReporting = 'basic';
    let managedPlatformUpdates = 'false';
    let cloudwatchStreamLogs = 'false';

    const result = await retry(async () => {
      return await this.elasticbeanstalk.send(new DescribeConfigurationSettingsCommand({
        ApplicationName: applicationName,
        EnvironmentName: envName,
      }));
    });
    const settings: any[] = result.ConfigurationSettings ?? [];
    const optionSettings: any[] = settings.length > 0 ? (settings[0].OptionSettings ?? []) : [];
    for (const option of optionSettings) {
      if (option.Namespace === 'aws:elasticbeanstalk:healthreporting:system' && option.OptionName === 'SystemType') {
        healthReporting = option.Value ?? 'basic';
      } else if (option.Namespace === 'aws:elasticbeanstalk:managedactions' && option.OptionName === 'ManagedActionsEnabled') {
        managedPlatformUpdates = option.Value ?? 'false';
      } else if (option.Namespace === 'aws:elasticbeanstalk:cloudwatch:logs' && option.OptionName === 'StreamLogs') {
        cloudwatchStreamLogs = option.Value ?? 'false';
      }
    }

    // elasticbeanstalk_environment_cloudwatch_logging_enabled: StreamLogs must be "true"
    if (cloudwatchStreamLogs !== 'true') {
      findings.push(this.emit(
        'elasticbeanstalk_environment_cloudwatch_logging_enabled',
        { environment: envName, application: applicationName, arn, streamLogs: cloudwatchStreamLogs },
        {
          message: `Elastic Beanstalk environment "${envName}" is not sending logs to CloudWatch Logs`,
          remediation: `Enable log streaming (StreamLogs=true in aws:elasticbeanstalk:cloudwatch:logs) on environment "${envName}"`,
        }
      ));
    }

    // elasticbeanstalk_environment_enhanced_health_reporting: SystemType must be "enhanced"
    if (healthReporting !== 'enhanced') {
      findings.push(this.emit(
        'elasticbeanstalk_environment_enhanced_health_reporting',
        { environment: envName, application: applicationName, arn, healthReporting },
        {
          message: `Elastic Beanstalk environment "${envName}" does not have enhanced health reporting enabled`,
          remediation: `Set SystemType=enhanced (aws:elasticbeanstalk:healthreporting:system) on environment "${envName}"`,
        }
      ));
    }

    // elasticbeanstalk_environment_managed_updates_enabled: ManagedActionsEnabled must be "true"
    if (managedPlatformUpdates !== 'true') {
      findings.push(this.emit(
        'elasticbeanstalk_environment_managed_updates_enabled',
        { environment: envName, application: applicationName, arn, managedActionsEnabled: managedPlatformUpdates },
        {
          message: `Elastic Beanstalk environment "${envName}" does not have managed platform updates enabled`,
          remediation: `Enable managed actions (ManagedActionsEnabled=true in aws:elasticbeanstalk:managedactions) with a maintenance window on environment "${envName}"`,
        }
      ));
    }

    return findings;
  }
}

export default ElasticBeanstalkScanner;
