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
import AccountScanner from './account';
import ACMPCAScanner from './acmpca';
import AmplifyScanner from './amplify';
import APIGatewayV2Scanner from './apigatewayv2';
import AppStreamScanner from './appstream';
import AppSyncScanner from './appsync';
import AthenaScanner from './athena';
import AutoScalingScanner from './autoscaling';
import BedrockScanner from './bedrock';
import CloudFormationScanner from './cloudformation';
import CodeBuildScanner from './codebuild';
import CodePipelineScanner from './codepipeline';
import DirectoryServiceScanner from './directoryservice';
import DMSScanner from './dms';
import DocumentDBScanner from './documentdb';
import ElasticBeanstalkScanner from './elasticbeanstalk';
import EMRScanner from './emr';
import EventBridgeScanner from './eventbridge';
import FirehoseScanner from './firehose';
import FMSScanner from './fms';
import FSxScanner from './fsx';
import KafkaScanner from './kafka';
import LightsailScanner from './lightsail';
import MemoryDBScanner from './memorydb';
import MQScanner from './mq';
import NeptuneScanner from './neptune';
import NetworkFirewallScanner from './networkfirewall';
import OrganizationsScanner from './organizations';
import RolesAnywhereScanner from './rolesanywhere';
import SageMakerScanner from './sagemaker';
import SESScanner from './ses';
import StepFunctionsScanner from './stepfunctions';
import StorageGatewayScanner from './storagegateway';
import TransferScanner from './transfer';
import WorkSpacesScanner from './workspaces';
import AccessAnalyzerScanner from './accessanalyzer';
import CodeArtifactScanner from './codeartifact';
import ConfigScanner from './config';
import ResourceExplorer2Scanner from './resourceexplorer2';
import SecurityHubScanner from './securityhub';
import ServiceCatalogScanner from './servicecatalog';
import ShieldScanner from './shield';
import SSMIncidentsScanner from './ssmincidents';
import TrustedAdvisorScanner from './trustedadvisor';
import WellArchitectedScanner from './wellarchitected';
import CodeCommitScanner from './codecommit';
import DataPipelineScanner from './datapipeline';
import { DescribeVpcsCommand } from '@aws-sdk/client-ec2';
import { ResourceGroupsTaggingAPIClient, GetResourcesCommand } from '@aws-sdk/client-resource-groups-tagging-api';
import { ScanningResult, ScanReport, ScanOptions, generateId } from '../utils/types';
import logger from '../utils/logger';

export class ScanEngine {
  // All standard (always-enabled) AWS commercial regions — excludes opt-in
  // regions (af-south-1, ap-east-1, eu-south-*, me-*, il-central-1, etc.)
  // that require the account to explicitly enable them first, since scanning
  // those without opt-in just errors on every call.
  private awsRegions: string[] = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'ca-central-1',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1',
    'sa-east-1',
  ];

  /**
   * Broad, cheap existence probe for one region: Resource Groups Tagging API
   * covers most taggable resource types (EC2, RDS, Lambda, S3-adjacent, etc.)
   * in a single call. Paired with a *non-default* VPC check — AWS creates an
   * untouched default VPC in every enabled region, so checking for "any VPC"
   * would never skip anything; a custom VPC is a real signal, a stock
   * default one isn't. Errs toward "has resources" on any probe failure
   * (e.g. a permissions gap) rather than silently dropping a region we
   * couldn't actually verify.
   */
  private async regionHasResources(client: AWSClient, region: string): Promise<boolean> {
    try {
      const tagging = new ResourceGroupsTaggingAPIClient(client.getClientConfig());
      const tagged = await tagging.send(new GetResourcesCommand({ ResourcesPerPage: 1 }));
      tagging.destroy();
      if ((tagged.ResourceTagMappingList ?? []).length > 0) return true;
    } catch (error) {
      logger.debug(`[region-precheck] tagging API probe failed in ${region}`, { error: (error as Error).message });
      return true; // can't verify — scan it rather than risk a false skip
    }
    try {
      const vpcs = await client.ec2.send(new DescribeVpcsCommand({
        Filters: [{ Name: 'isDefault', Values: ['false'] }],
        MaxResults: 5,
      }));
      if ((vpcs.Vpcs ?? []).length > 0) return true;
    } catch (error) {
      logger.debug(`[region-precheck] DescribeVpcs probe failed in ${region}`, { error: (error as Error).message });
      return true;
    }
    return false;
  }

  /**
   * Drop regions with zero detected resources before the full ~87-service
   * scan set runs against them — most accounts only use a handful of the 17
   * standard regions, so this cuts wasted API calls/time substantially.
   * Global/account-level services (IAM, S3, CloudTrail, Route53, ...) are
   * unaffected — they still run exactly once, against whichever region ends
   * up first in the filtered list (see the "Account-level" block below).
   */
  private async filterActiveRegions(regions: string[], options: ScanOptions): Promise<string[]> {
    const active: string[] = [];
    for (const region of regions) {
      const client = options._explicitCredentials
        ? new AWSClient(region, undefined, options._explicitCredentials)
        : CredentialsManager.validateAndCreateClient(region, options.profile);
      try {
        if (await this.regionHasResources(client, region)) {
          active.push(region);
        } else {
          logger.info(`Skipping region ${region} — no resources detected`);
        }
      } finally {
        await client.cleanup();
      }
    }
    // Never end up with zero regions — always scan at least one so
    // account-level/global services still run somewhere.
    return active.length > 0 ? active : [regions[0]];
  }

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

      const requestedRegions = options.regions || [options.region || 'us-east-1'];
      const services = options.services || this.getAvailableServices();
      const regions = options.dryRun
        ? requestedRegions
        : await this.filterActiveRegions(requestedRegions, options);

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
            if (services.includes('account')) {
              findings.push(...await new AccountScanner(client).scan(options));
            }
            if (services.includes('organizations')) {
              findings.push(...await new OrganizationsScanner(client).scan(options));
            }
            // FMS is global — the scanner pins us-east-1 internally
            if (services.includes('fms')) {
              findings.push(...await new FMSScanner(client).scan(options));
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
          if (services.includes('acmpca')) {
            findings.push(...await new ACMPCAScanner(client).scan(options));
          }
          if (services.includes('amplify')) {
            findings.push(...await new AmplifyScanner(client).scan(options));
          }
          if (services.includes('apigatewayv2')) {
            findings.push(...await new APIGatewayV2Scanner(client).scan(options));
          }
          if (services.includes('appstream')) {
            findings.push(...await new AppStreamScanner(client).scan(options));
          }
          if (services.includes('appsync')) {
            findings.push(...await new AppSyncScanner(client).scan(options));
          }
          if (services.includes('athena')) {
            findings.push(...await new AthenaScanner(client).scan(options));
          }
          if (services.includes('autoscaling')) {
            findings.push(...await new AutoScalingScanner(client).scan(options));
          }
          if (services.includes('bedrock')) {
            findings.push(...await new BedrockScanner(client).scan(options));
          }
          if (services.includes('cloudformation')) {
            findings.push(...await new CloudFormationScanner(client).scan(options));
          }
          if (services.includes('codebuild')) {
            findings.push(...await new CodeBuildScanner(client).scan(options));
          }
          if (services.includes('codepipeline')) {
            findings.push(...await new CodePipelineScanner(client).scan(options));
          }
          if (services.includes('directoryservice')) {
            findings.push(...await new DirectoryServiceScanner(client).scan(options));
          }
          if (services.includes('dms')) {
            findings.push(...await new DMSScanner(client).scan(options));
          }
          if (services.includes('documentdb')) {
            findings.push(...await new DocumentDBScanner(client).scan(options));
          }
          if (services.includes('elasticbeanstalk')) {
            findings.push(...await new ElasticBeanstalkScanner(client).scan(options));
          }
          if (services.includes('emr')) {
            findings.push(...await new EMRScanner(client).scan(options));
          }
          if (services.includes('eventbridge')) {
            findings.push(...await new EventBridgeScanner(client).scan(options));
          }
          if (services.includes('firehose')) {
            findings.push(...await new FirehoseScanner(client).scan(options));
          }
          if (services.includes('fsx')) {
            findings.push(...await new FSxScanner(client).scan(options));
          }
          if (services.includes('kafka')) {
            findings.push(...await new KafkaScanner(client).scan(options));
          }
          if (services.includes('lightsail')) {
            findings.push(...await new LightsailScanner(client).scan(options));
          }
          if (services.includes('memorydb')) {
            findings.push(...await new MemoryDBScanner(client).scan(options));
          }
          if (services.includes('mq')) {
            findings.push(...await new MQScanner(client).scan(options));
          }
          if (services.includes('neptune')) {
            findings.push(...await new NeptuneScanner(client).scan(options));
          }
          if (services.includes('networkfirewall')) {
            findings.push(...await new NetworkFirewallScanner(client).scan(options));
          }
          if (services.includes('rolesanywhere')) {
            findings.push(...await new RolesAnywhereScanner(client).scan(options));
          }
          if (services.includes('sagemaker')) {
            findings.push(...await new SageMakerScanner(client).scan(options));
          }
          if (services.includes('ses')) {
            findings.push(...await new SESScanner(client).scan(options));
          }
          if (services.includes('stepfunctions')) {
            findings.push(...await new StepFunctionsScanner(client).scan(options));
          }
          if (services.includes('storagegateway')) {
            findings.push(...await new StorageGatewayScanner(client).scan(options));
          }
          if (services.includes('transfer')) {
            findings.push(...await new TransferScanner(client).scan(options));
          }
          if (services.includes('workspaces')) {
            findings.push(...await new WorkSpacesScanner(client).scan(options));
          }
          if (services.includes('accessanalyzer')) {
            findings.push(...await new AccessAnalyzerScanner(client).scan(options));
          }
          if (services.includes('codeartifact')) {
            findings.push(...await new CodeArtifactScanner(client).scan(options));
          }
          if (services.includes('securityhub')) {
            findings.push(...await new SecurityHubScanner(client).scan(options));
          }
          if (services.includes('servicecatalog')) {
            findings.push(...await new ServiceCatalogScanner(client).scan(options));
          }
          if (services.includes('ssmincidents')) {
            findings.push(...await new SSMIncidentsScanner(client).scan(options));
          }
          if (services.includes('wellarchitected')) {
            findings.push(...await new WellArchitectedScanner(client).scan(options));
          }
          if (services.includes('codecommit')) {
            findings.push(...await new CodeCommitScanner(client).scan(options));
          }
          if (services.includes('datapipeline')) {
            findings.push(...await new DataPipelineScanner(client).scan(options));
          }

        } finally {
          await client.cleanup();
        }
      }

      const duration = Date.now() - startTime;

      // Threat Detection (service THREAT) findings are anomaly/behavioral
      // signals, not static configuration posture — excluded from the
      // aggregate summary so they don't inflate the Critical/High counts
      // shown across Reports, account headers, and the VAPT report exec
      // summary. Still returned in `findings` below (and so still stored
      // and visible on the dedicated Threat Detection page).
      const postureFindings = findings.filter(f => f.service !== 'THREAT');

      const report: ScanReport = {
        id: generateId(),
        timestamp: new Date(),
        account: '123456789012',
        regions,
        services,
        totalFindings: postureFindings.length,
        findings,
        summary: {
          critical: postureFindings.filter(f => f.severity === 'CRITICAL').length,
          high:     postureFindings.filter(f => f.severity === 'HIGH').length,
          medium:   postureFindings.filter(f => f.severity === 'MEDIUM').length,
          low:      postureFindings.filter(f => f.severity === 'LOW').length,
          info:     postureFindings.filter(f => f.severity === 'INFO').length,
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
      'account', 'organizations', 'fms',
      'acmpca', 'amplify', 'apigatewayv2', 'appstream', 'appsync',
      'athena', 'autoscaling', 'bedrock', 'cloudformation',
      'codebuild', 'codepipeline', 'directoryservice', 'dms',
      'documentdb', 'elasticbeanstalk', 'emr', 'eventbridge',
      'firehose', 'fsx', 'kafka', 'lightsail', 'memorydb', 'mq',
      'neptune', 'networkfirewall', 'rolesanywhere', 'sagemaker',
      'ses', 'stepfunctions', 'storagegateway', 'transfer', 'workspaces',
      'accessanalyzer', 'codeartifact', 'config', 'resourceexplorer2',
      'securityhub', 'servicecatalog', 'shield', 'ssmincidents',
      'trustedadvisor', 'wellarchitected', 'codecommit', 'datapipeline',
    ];
  }
}

export default ScanEngine;
