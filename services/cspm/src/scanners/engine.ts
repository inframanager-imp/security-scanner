import CredentialsManager from '../aws/credentials';
import AWSClient from '../aws/client';
import CloudTrailScanner from './cloudtrail';
import IAMScanner from './iam';
import S3Scanner from './s3';
import EC2Scanner from './ec2';
import RDSScanner from './rds';
import KMSScanner from './kms';
import SecretsManagerScanner from './secretsmanager';
import CloudWatchScanner from './cloudwatch';
import VPCScanner from './vpc';
import LambdaScanner from './lambda';
import ECRScanner from './ecr';
import ThreatDetectionScanner from './threatdetection';
import EBSScanner from './ebs';
import ELBScanner from './elb';
import DynamoDBScanner from './dynamodb';
import ElastiCacheScanner from './elasticache';
import APIGatewayScanner from './apigateway';
import WAFScanner from './waf';
import SSMScanner from './ssm';
import CloudFrontScanner from './cloudfront';
import ACMScanner from './acm';
import SNSScanner from './sns';
import SQSScanner from './sqs';
import RedshiftScanner from './redshift';
import ECSScanner from './ecs';
import { ScanningResult, ScanReport, ScanOptions, generateId } from '../utils/types';
import logger from '../utils/logger';

export class ScanEngine {
  private awsRegions: string[] = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1'
  ];

  async executeScan(options: ScanOptions): Promise<ScanReport> {
    const startTime = Date.now();
    const findings: ScanningResult[] = [];

    try {
      logger.info('=== AWS Security Scan Starting ===');

      if (!CredentialsManager.validateCredentials()) {
        throw new Error('AWS credentials not configured');
      }

      const regions  = options.regions  || [options.region || 'us-east-1'];
      const services = options.services || this.getAvailableServices();

      for (const region of regions) {
        logger.info(`Scanning region: ${region}`);

        const client = options._explicitCredentials
          ? new AWSClient(region, undefined, options._explicitCredentials)
          : CredentialsManager.validateAndCreateClient(region, options.profile);

        await client.getAccountId();

        if (options.dryRun) {
          logger.info(`[DRY RUN] Would scan region ${region}`);
          await client.cleanup();
          continue;
        }

        try {
          // ── Account-level (run once, first region only) ───────────────────

          if (region === regions[0]) {
            if (services.includes('cloudtrail')) {
              findings.push(...await new CloudTrailScanner(client).scan(options));
            }
            if (services.includes('iam')) {
              findings.push(...await new IAMScanner(client).scan(options));
            }
            if (services.includes('s3')) {
              findings.push(...await new S3Scanner(client).scan(options));
            }
            if (services.includes('threatdetection')) {
              findings.push(...await new ThreatDetectionScanner(client).scan(options));
            }
            // CloudFront is global — hosted in us-east-1
            if (services.includes('cloudfront') && region === 'us-east-1') {
              findings.push(...await new CloudFrontScanner(client).scan(options));
            }
          }

          // ── Region-specific ───────────────────────────────────────────────

          if (services.includes('ec2')) {
            findings.push(...await new EC2Scanner(client).scan(options));
          }
          if (services.includes('ebs')) {
            findings.push(...await new EBSScanner(client).scan(options));
          }
          if (services.includes('rds')) {
            findings.push(...await new RDSScanner(client).scan(options));
          }
          if (services.includes('kms')) {
            findings.push(...await new KMSScanner(client).scan(options));
          }
          if (services.includes('secretsmanager')) {
            findings.push(...await new SecretsManagerScanner(client).scan(options));
          }
          if (services.includes('cloudwatch')) {
            findings.push(...await new CloudWatchScanner(client).scan(options));
          }
          if (services.includes('vpc')) {
            findings.push(...await new VPCScanner(client).scan(options));
          }
          if (services.includes('lambda')) {
            findings.push(...await new LambdaScanner(client).scan(options));
          }
          if (services.includes('ecr')) {
            findings.push(...await new ECRScanner(client).scan({ lastScanAt: options.lastScanAt }));
          }
          if (services.includes('elb')) {
            findings.push(...await new ELBScanner(client).scan(options));
          }
          if (services.includes('dynamodb')) {
            findings.push(...await new DynamoDBScanner(client).scan(options));
          }
          if (services.includes('elasticache')) {
            findings.push(...await new ElastiCacheScanner(client).scan(options));
          }
          if (services.includes('apigateway')) {
            findings.push(...await new APIGatewayScanner(client).scan(options));
          }
          if (services.includes('waf')) {
            findings.push(...await new WAFScanner(client).scan(options));
          }
          if (services.includes('ssm')) {
            findings.push(...await new SSMScanner(client).scan(options));
          }
          if (services.includes('acm')) {
            findings.push(...await new ACMScanner(client).scan(options));
          }
          if (services.includes('sns')) {
            findings.push(...await new SNSScanner(client).scan(options));
          }
          if (services.includes('sqs')) {
            findings.push(...await new SQSScanner(client).scan(options));
          }
          if (services.includes('redshift')) {
            findings.push(...await new RedshiftScanner(client).scan(options));
          }
          if (services.includes('ecs')) {
            findings.push(...await new ECSScanner(client).scan(options));
          }

        } finally {
          await client.cleanup();
        }
      }

      const duration = Date.now() - startTime;

      const report: ScanReport = {
        id: generateId(),
        timestamp: new Date(),
        account: '123456789012',
        regions,
        services,
        totalFindings: findings.length,
        findings,
        summary: {
          critical: findings.filter(f => f.severity === 'CRITICAL').length,
          high:     findings.filter(f => f.severity === 'HIGH').length,
          medium:   findings.filter(f => f.severity === 'MEDIUM').length,
          low:      findings.filter(f => f.severity === 'LOW').length,
          info:     findings.filter(f => f.severity === 'INFO').length,
        },
        duration,
      };

      logger.info(`=== Scan Complete === ${findings.length} findings in ${duration}ms`);
      return report;

    } catch (error) {
      logger.error('Scan failed', { error: (error as Error).message });
      throw error;
    }
  }

  getAvailableRegions(): string[] {
    return this.awsRegions;
  }

  getAvailableServices(): string[] {
    return [
      'cloudtrail', 'iam', 's3',
      'ec2', 'ebs', 'rds', 'kms', 'secretsmanager',
      'cloudwatch', 'vpc', 'lambda', 'ecr',
      'threatdetection',
      'elb', 'dynamodb', 'elasticache',
      'apigateway', 'waf', 'ssm',
      'cloudfront', 'acm',
      'sns', 'sqs', 'redshift', 'ecs',
    ];
  }
}

export default ScanEngine;
