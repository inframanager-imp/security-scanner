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
import BackupScanner from './backup';
import CognitoScanner from './cognito';
import KinesisScanner from './kinesis';
import GlueScanner from './glue';
import EKSScanner from './eks';
import EFSScanner from './efs';
import Route53Scanner from './route53';
import OpenSearchScanner from './opensearch';
import DataSyncScanner from './datasync';
import DirectConnectScanner from './directconnect';
import DLMScanner from './dlm';
import DRSScanner from './drs';
import GlacierScanner from './glacier';
import MacieScanner from './macie';
import Inspector2Scanner from './inspector2';
import AccessAnalyzerScanner from './accessanalyzer';
import CodeArtifactScanner from './codeartifact';
import CodeCommitScanner from './codecommit';
import ConfigScanner from './config';
import DataPipelineScanner from './datapipeline';
import ResourceExplorer2Scanner from './resourceexplorer2';
import SecurityHubScanner from './securityhub';
import ServiceCatalogScanner from './servicecatalog';
import ShieldScanner from './shield';
import SSMIncidentsScanner from './ssmincidents';
import TrustedAdvisorScanner from './trustedadvisor';
import WellArchitectedScanner from './wellarchitected';
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

      // Per-account credentials (from the DB, passed by the scan worker) are the
      // normal path; only fall back to requiring env/profile creds when none were
      // supplied explicitly.
      if (!options._explicitCredentials && !CredentialsManager.validateCredentials()) {
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
            // Route53 is global — scan once with the first region's client
            if (services.includes('route53')) {
              findings.push(...await new Route53Scanner(client).scan(options));
            }
            // Shield and Trusted Advisor are global — scanners pin us-east-1 internally
            if (services.includes('shield')) {
              findings.push(...await new ShieldScanner(client).scan(options));
            }
            if (services.includes('trustedadvisor')) {
              findings.push(...await new TrustedAdvisorScanner(client).scan(options));
            }
            // Resource Explorer ListIndexes reports indexes across all regions
            if (services.includes('resourceexplorer2')) {
              findings.push(...await new ResourceExplorer2Scanner(client).scan(options));
            }
            // Config org-aggregator check is account-level; run once in the first region
            if (services.includes('config')) {
              findings.push(...await new ConfigScanner(client).scan(options));
            }
            // Security Hub delegated-admin check is org-level; run once in the first region
            if (services.includes('securityhub')) {
              findings.push(...await new SecurityHubScanner(client).scan(options));
            }
            // SSM Incident Manager response plans are account-level
            if (services.includes('ssmincidents')) {
              findings.push(...await new SSMIncidentsScanner(client).scan(options));
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
          if (services.includes('backup')) {
            findings.push(...await new BackupScanner(client).scan(options));
          }
          if (services.includes('cognito')) {
            findings.push(...await new CognitoScanner(client).scan(options));
          }
          if (services.includes('kinesis')) {
            findings.push(...await new KinesisScanner(client).scan(options));
          }
          if (services.includes('glue')) {
            findings.push(...await new GlueScanner(client).scan(options));
          }
          if (services.includes('eks')) {
            findings.push(...await new EKSScanner(client).scan(options));
          }
          if (services.includes('efs')) {
            findings.push(...await new EFSScanner(client).scan(options));
          }
          if (services.includes('opensearch')) {
            findings.push(...await new OpenSearchScanner(client).scan(options));
          }
          if (services.includes('datasync')) {
            findings.push(...await new DataSyncScanner(client).scan(options));
          }
          if (services.includes('directconnect')) {
            findings.push(...await new DirectConnectScanner(client).scan(options));
          }
          if (services.includes('dlm')) {
            findings.push(...await new DLMScanner(client).scan(options));
          }
          if (services.includes('drs')) {
            findings.push(...await new DRSScanner(client).scan(options));
          }
          if (services.includes('glacier')) {
            findings.push(...await new GlacierScanner(client).scan(options));
          }
          if (services.includes('macie')) {
            findings.push(...await new MacieScanner(client).scan(options));
          }
          if (services.includes('inspector2')) {
            findings.push(...await new Inspector2Scanner(client).scan(options));
          }
          if (services.includes('accessanalyzer')) {
            findings.push(...await new AccessAnalyzerScanner(client).scan(options));
          }
          if (services.includes('codeartifact')) {
            findings.push(...await new CodeArtifactScanner(client).scan(options));
          }
          if (services.includes('codecommit')) {
            findings.push(...await new CodeCommitScanner(client).scan(options));
          }
          if (services.includes('datapipeline')) {
            findings.push(...await new DataPipelineScanner(client).scan(options));
          }
          if (services.includes('servicecatalog')) {
            findings.push(...await new ServiceCatalogScanner(client).scan(options));
          }
          if (services.includes('wellarchitected')) {
            findings.push(...await new WellArchitectedScanner(client).scan(options));
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
      'backup', 'cognito', 'kinesis', 'glue',
      'eks', 'efs', 'route53', 'opensearch',
      'datasync', 'directconnect', 'dlm', 'drs', 'glacier',
      'macie', 'inspector2',
      'accessanalyzer', 'codeartifact', 'codecommit', 'config',
      'datapipeline', 'resourceexplorer2', 'securityhub', 'servicecatalog',
      'shield', 'ssmincidents', 'trustedadvisor', 'wellarchitected',
    ];
  }
}

export default ScanEngine;
