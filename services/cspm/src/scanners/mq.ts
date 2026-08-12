// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  MqClient,
  ListBrokersCommand,
  DescribeBrokerCommand,
} from '@aws-sdk/client-mq';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class MQScanner extends BaseScanner {
  private mq: MqClient;

  constructor(client: AWSClient) {
    super(client, 'MQ');
    this.mq = new MqClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting MQ security scan...');

      const brokers = await this.listBrokers();
      for (const summary of brokers) {
        const brokerName: string = summary.BrokerName ?? '';
        const brokerId: string = summary.BrokerId ?? '';
        logger.debug(`Scanning MQ broker: ${brokerName}`);
        try {
          const brokerFindings = await this.validateBroker(brokerId, brokerName, summary.BrokerArn ?? '');
          findings.push(...brokerFindings);
        } catch (error) {
          logger.debug(`Failed to scan MQ broker ${brokerName}`, { error: (error as Error).message });
        }
      }

      logger.info(`MQ scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('MQ scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listBrokers(): Promise<any[]> {
    const brokers: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.mq.send(new ListBrokersCommand({ NextToken: nextToken }));
      });
      brokers.push(...(result.BrokerSummaries ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return brokers;
  }

  private async validateBroker(brokerId: string, brokerName: string, brokerArn: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const broker: any = await retry(async () => {
      return await this.mq.send(new DescribeBrokerCommand({ BrokerId: brokerId }));
    });

    const engineType: string = String(broker.EngineType ?? 'ACTIVEMQ').toUpperCase();
    const deploymentMode: string = String(broker.DeploymentMode ?? 'SINGLE_INSTANCE').toUpperCase();

    // mq_broker_not_publicly_accessible
    if (broker.PubliclyAccessible) {
      findings.push(this.emit(
        'mq_broker_not_publicly_accessible',
        { broker: brokerName, arn: brokerArn, publiclyAccessible: true },
        {
          message: `MQ broker "${brokerName}" is publicly accessible`,
          remediation: `Redeploy broker "${brokerName}" as non-publicly accessible in private subnets and restrict security groups to trusted producers and consumers`,
        }
      ));
    }

    // mq_broker_active_deployment_mode: ActiveMQ brokers should use ACTIVE_STANDBY_MULTI_AZ
    if (engineType === 'ACTIVEMQ' && deploymentMode !== 'ACTIVE_STANDBY_MULTI_AZ') {
      findings.push(this.emit(
        'mq_broker_active_deployment_mode',
        { broker: brokerName, arn: brokerArn, engineType, deploymentMode },
        {
          message: `MQ ActiveMQ broker "${brokerName}" does not use the active/standby multi-AZ deployment mode (current: ${deploymentMode})`,
        }
      ));
    }

    // mq_broker_cluster_deployment_mode: RabbitMQ brokers should use CLUSTER_MULTI_AZ
    if (engineType === 'RABBITMQ' && deploymentMode !== 'CLUSTER_MULTI_AZ') {
      findings.push(this.emit(
        'mq_broker_cluster_deployment_mode',
        { broker: brokerName, arn: brokerArn, engineType, deploymentMode },
        {
          message: `MQ RabbitMQ broker "${brokerName}" does not use the cluster multi-AZ deployment mode (current: ${deploymentMode})`,
        }
      ));
    }

    // mq_broker_auto_minor_version_upgrades
    if (!broker.AutoMinorVersionUpgrade) {
      findings.push(this.emit(
        'mq_broker_auto_minor_version_upgrades',
        { broker: brokerName, arn: brokerArn, autoMinorVersionUpgrade: false },
        {
          message: `MQ broker "${brokerName}" does not have automatic minor version upgrades enabled`,
        }
      ));
    }

    // mq_broker_logging_enabled: general logging (plus audit logging for ActiveMQ)
    const generalLogging: boolean = broker.Logs?.General ?? false;
    const auditLogging: boolean = broker.Logs?.Audit ?? false;
    let loggingEnabled = false;
    if (engineType === 'ACTIVEMQ') {
      loggingEnabled = generalLogging && auditLogging;
    } else if (engineType === 'RABBITMQ') {
      loggingEnabled = generalLogging;
    }
    if (!loggingEnabled) {
      findings.push(this.emit(
        'mq_broker_logging_enabled',
        { broker: brokerName, arn: brokerArn, engineType, generalLogging, auditLogging },
        {
          message: `MQ broker "${brokerName}" does not have logging enabled (general: ${generalLogging}, audit: ${auditLogging})`,
          remediation: engineType === 'ACTIVEMQ'
            ? `Enable both general and audit logging on ActiveMQ broker "${brokerName}"`
            : `Enable general logging on broker "${brokerName}"`,
        }
      ));
    }

    return findings;
  }
}

export default MQScanner;
