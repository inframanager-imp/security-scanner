import { CheckMetadata } from '../../types';
import { accessanalyzerChecks } from './accessanalyzer';
import { codeartifactChecks } from './codeartifact';
import { codecommitChecks } from './codecommit';
import { configChecks } from './config';
import { datapipelineChecks } from './datapipeline';
import { resourceexplorer2Checks } from './resourceexplorer2';
import { securityhubChecks } from './securityhub';
import { servicecatalogChecks } from './servicecatalog';
import { shieldChecks } from './shield';
import { ssmincidentsChecks } from './ssmincidents';
import { trustedadvisorChecks } from './trustedadvisor';
import { wellarchitectedChecks } from './wellarchitected';
import { s3Checks } from './s3';
import { iamChecks } from './iam';
import { ec2Checks } from './ec2';
import { vpcChecks } from './vpc';
import { cloudwatchChecks } from './cloudwatch';
import { cloudtrailChecks } from './cloudtrail';
import { ebsChecks } from './ebs';
import { threatdetectionChecks } from './threatdetection';
import { rdsChecks } from './rds';
import { kmsChecks } from './kms';
import { secretsmanagerChecks } from './secretsmanager';
import { lambdaChecks } from './lambda';
import { ecrChecks } from './ecr';
import { elbChecks } from './elb';
import { dynamodbChecks } from './dynamodb';
import { elasticacheChecks } from './elasticache';
import { apigatewayChecks } from './apigateway';
import { wafChecks } from './waf';
import { ssmChecks } from './ssm';
import { cloudfrontChecks } from './cloudfront';
import { acmChecks } from './acm';
import { snsChecks } from './sns';
import { sqsChecks } from './sqs';
import { redshiftChecks } from './redshift';
import { ecsChecks } from './ecs';
import { backupChecks } from './backup';
import { cognitoChecks } from './cognito';
import { kinesisChecks } from './kinesis';
import { glueChecks } from './glue';
import { eksChecks } from './eks';
import { efsChecks } from './efs';
import { route53Checks } from './route53';
import { opensearchChecks } from './opensearch';
import { datasyncChecks } from './datasync';
import { directconnectChecks } from './directconnect';
import { dlmChecks } from './dlm';
import { drsChecks } from './drs';
import { glacierChecks } from './glacier';
import { macieChecks } from './macie';
import { inspector2Checks } from './inspector2';

export const awsChecks: CheckMetadata[] = [
  ...accessanalyzerChecks,
  ...codeartifactChecks,
  ...codecommitChecks,
  ...configChecks,
  ...datapipelineChecks,
  ...resourceexplorer2Checks,
  ...securityhubChecks,
  ...servicecatalogChecks,
  ...shieldChecks,
  ...ssmincidentsChecks,
  ...trustedadvisorChecks,
  ...wellarchitectedChecks,
  ...s3Checks,
  ...iamChecks,
  ...ec2Checks,
  ...vpcChecks,
  ...cloudwatchChecks,
  ...cloudtrailChecks,
  ...ebsChecks,
  ...threatdetectionChecks,
  ...rdsChecks,
  ...kmsChecks,
  ...secretsmanagerChecks,
  ...lambdaChecks,
  ...ecrChecks,
  ...elbChecks,
  ...dynamodbChecks,
  ...elasticacheChecks,
  ...apigatewayChecks,
  ...wafChecks,
  ...ssmChecks,
  ...cloudfrontChecks,
  ...acmChecks,
  ...snsChecks,
  ...sqsChecks,
  ...redshiftChecks,
  ...ecsChecks,
  ...backupChecks,
  ...cognitoChecks,
  ...kinesisChecks,
  ...glueChecks,
  ...eksChecks,
  ...efsChecks,
  ...route53Checks,
  ...opensearchChecks,
  ...datasyncChecks,
  ...directconnectChecks,
  ...dlmChecks,
  ...drsChecks,
  ...glacierChecks,
  ...macieChecks,
  ...inspector2Checks,
];

