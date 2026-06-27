import {
  STSClient,
  GetCallerIdentityCommand,
  AssumeRoleCommand
} from '@aws-sdk/client-sts';
import { CloudTrailClient } from '@aws-sdk/client-cloudtrail';
import { IAMClient } from '@aws-sdk/client-iam';
import { S3Client } from '@aws-sdk/client-s3';
import { EC2Client } from '@aws-sdk/client-ec2';
import { RDSClient } from '@aws-sdk/client-rds';
import { KMSClient } from '@aws-sdk/client-kms';
import { CloudWatchClient } from '@aws-sdk/client-cloudwatch';
import { CloudWatchLogsClient } from '@aws-sdk/client-cloudwatch-logs';
import { LambdaClient } from '@aws-sdk/client-lambda';
import { ECRClient } from '@aws-sdk/client-ecr';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { ElasticLoadBalancingV2Client } from '@aws-sdk/client-elastic-load-balancing-v2';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { ElastiCacheClient } from '@aws-sdk/client-elasticache';
import { APIGatewayClient } from '@aws-sdk/client-api-gateway';
import { WAFV2Client } from '@aws-sdk/client-wafv2';
import { SSMClient } from '@aws-sdk/client-ssm';
import { CloudFrontClient } from '@aws-sdk/client-cloudfront';
import { ACMClient } from '@aws-sdk/client-acm';
import { SNSClient } from '@aws-sdk/client-sns';
import { SQSClient } from '@aws-sdk/client-sqs';
import { RedshiftClient } from '@aws-sdk/client-redshift';
import { ECSClient } from '@aws-sdk/client-ecs';
import { fromEnv, fromIni } from '@aws-sdk/credential-providers';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class AWSClient {
  private region: string;
  private accountId?: string;

  // Service clients
  sts: STSClient;
  cloudtrail: CloudTrailClient;
  iam: IAMClient;
  s3: S3Client;
  ec2: EC2Client;
  rds: RDSClient;
  kms: KMSClient;
  cloudwatch: CloudWatchClient;
  logs: CloudWatchLogsClient;
  lambda: LambdaClient;
  ecr: ECRClient;
  secretsmanager: SecretsManagerClient;
  elbv2: ElasticLoadBalancingV2Client;
  dynamodb: DynamoDBClient;
  elasticache: ElastiCacheClient;
  apigateway: APIGatewayClient;
  wafv2: WAFV2Client;
  ssm: SSMClient;
  cloudfront: CloudFrontClient;
  acm: ACMClient;
  sns: SNSClient;
  sqs: SQSClient;
  redshift: RedshiftClient;
  ecs: ECSClient;

  constructor(
    region: string = 'us-east-1',
    profile?: string,
    explicitCredentials?: { accessKeyId: string; secretAccessKey: string; sessionToken?: string }
  ) {
    this.region = region;

    const credentials = explicitCredentials
      ? explicitCredentials
      : profile ? fromIni({ profile }) : fromEnv();
    const clientConfig = { region, credentials };

    this.sts            = new STSClient(clientConfig);
    this.cloudtrail     = new CloudTrailClient(clientConfig);
    this.iam            = new IAMClient(clientConfig);
    this.s3             = new S3Client(clientConfig);
    this.ec2            = new EC2Client(clientConfig);
    this.rds            = new RDSClient(clientConfig);
    this.kms            = new KMSClient(clientConfig);
    this.cloudwatch     = new CloudWatchClient(clientConfig);
    this.logs           = new CloudWatchLogsClient(clientConfig);
    this.lambda         = new LambdaClient(clientConfig);
    this.ecr            = new ECRClient(clientConfig);
    this.secretsmanager = new SecretsManagerClient(clientConfig);
    this.elbv2          = new ElasticLoadBalancingV2Client(clientConfig);
    this.dynamodb       = new DynamoDBClient(clientConfig);
    this.elasticache    = new ElastiCacheClient(clientConfig);
    this.apigateway     = new APIGatewayClient(clientConfig);
    this.wafv2          = new WAFV2Client(clientConfig);
    this.ssm            = new SSMClient(clientConfig);
    this.cloudfront     = new CloudFrontClient(clientConfig);
    this.acm            = new ACMClient(clientConfig);
    this.sns            = new SNSClient(clientConfig);
    this.sqs            = new SQSClient(clientConfig);
    this.redshift       = new RedshiftClient(clientConfig);
    this.ecs            = new ECSClient(clientConfig);
  }

  async getAccountId(): Promise<string> {
    if (this.accountId) return this.accountId;
    return retry(async () => {
      const result = await this.sts.send(new GetCallerIdentityCommand({}));
      this.accountId = result.Account;
      if (!this.accountId) throw new Error('Unable to retrieve account ID');
      logger.info(`Current AWS Account: ${this.accountId}`);
      return this.accountId;
    });
  }

  async assumeRole(roleArn: string, sessionName: string, duration: number = 3600): Promise<void> {
    return retry(async () => {
      logger.info(`Assuming role: ${roleArn}`);
      const result = await this.sts.send(
        new AssumeRoleCommand({ RoleArn: roleArn, RoleSessionName: sessionName, DurationSeconds: duration })
      );
      if (!result.Credentials) throw new Error('No credentials returned from STS');

      const credentials = {
        accessKeyId:     result.Credentials.AccessKeyId!,
        secretAccessKey: result.Credentials.SecretAccessKey!,
        sessionToken:    result.Credentials.SessionToken,
      };
      const clientConfig = { region: this.region, credentials };

      this.cloudtrail     = new CloudTrailClient(clientConfig);
      this.iam            = new IAMClient(clientConfig);
      this.s3             = new S3Client(clientConfig);
      this.ec2            = new EC2Client(clientConfig);
      this.rds            = new RDSClient(clientConfig);
      this.kms            = new KMSClient(clientConfig);
      this.cloudwatch     = new CloudWatchClient(clientConfig);
      this.logs           = new CloudWatchLogsClient(clientConfig);
      this.lambda         = new LambdaClient(clientConfig);
      this.ecr            = new ECRClient(clientConfig);
      this.secretsmanager = new SecretsManagerClient(clientConfig);
      this.elbv2          = new ElasticLoadBalancingV2Client(clientConfig);
      this.dynamodb       = new DynamoDBClient(clientConfig);
      this.elasticache    = new ElastiCacheClient(clientConfig);
      this.apigateway     = new APIGatewayClient(clientConfig);
      this.wafv2          = new WAFV2Client(clientConfig);
      this.ssm            = new SSMClient(clientConfig);
      this.cloudfront     = new CloudFrontClient(clientConfig);
      this.acm            = new ACMClient(clientConfig);
      this.sns            = new SNSClient(clientConfig);
      this.sqs            = new SQSClient(clientConfig);
      this.redshift       = new RedshiftClient(clientConfig);
      this.ecs            = new ECSClient(clientConfig);
      logger.info('Role assumption successful');
    });
  }

  async validateAccess(): Promise<boolean> {
    try {
      await this.getAccountId();
      return true;
    } catch (error) {
      logger.error('AWS access validation failed', { error: (error as Error).message });
      return false;
    }
  }

  getRegion(): string { return this.region; }
  setRegion(region: string): void { this.region = region; }

  async cleanup(): Promise<void> {
    await Promise.allSettled([
      this.sts.destroy(),
      this.cloudtrail.destroy(),
      this.iam.destroy(),
      this.s3.destroy(),
      this.ec2.destroy(),
      this.rds.destroy(),
      this.kms.destroy(),
      this.cloudwatch.destroy(),
      this.logs.destroy(),
      this.lambda.destroy(),
      this.ecr.destroy(),
      this.secretsmanager.destroy(),
      this.elbv2.destroy(),
      this.dynamodb.destroy(),
      this.elasticache.destroy(),
      this.apigateway.destroy(),
      this.wafv2.destroy(),
      this.ssm.destroy(),
      this.cloudfront.destroy(),
      this.acm.destroy(),
      this.sns.destroy(),
      this.sqs.destroy(),
      this.redshift.destroy(),
      this.ecs.destroy(),
    ]);
  }
}

export default AWSClient;
