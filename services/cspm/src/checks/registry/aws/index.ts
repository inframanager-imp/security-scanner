import { CheckMetadata } from '../../types';
import { accessanalyzerChecks } from './accessanalyzer';
import { accountChecks } from './account';
import { acmChecks } from './acm';
import { acmpcaChecks } from './acmpca';
import { amplifyChecks } from './amplify';
import { apigatewayChecks } from './apigateway';
import { apigatewayv2Checks } from './apigatewayv2';
import { appstreamChecks } from './appstream';
import { appsyncChecks } from './appsync';
import { athenaChecks } from './athena';
import { autoscalingChecks } from './autoscaling';
import { backupChecks } from './backup';
import { bedrockChecks } from './bedrock';
import { cloudformationChecks } from './cloudformation';
import { cloudfrontChecks } from './cloudfront';
import { cloudtrailChecks } from './cloudtrail';
import { cloudwatchChecks } from './cloudwatch';
import { codeartifactChecks } from './codeartifact';
import { codebuildChecks } from './codebuild';
import { codecommitChecks } from './codecommit';
import { codepipelineChecks } from './codepipeline';
import { cognitoChecks } from './cognito';
import { configChecks } from './config';
import { datapipelineChecks } from './datapipeline';
import { datasyncChecks } from './datasync';
import { directconnectChecks } from './directconnect';
import { directoryserviceChecks } from './directoryservice';
import { dlmChecks } from './dlm';
import { dmsChecks } from './dms';
import { documentdbChecks } from './documentdb';
import { drsChecks } from './drs';
import { dynamodbChecks } from './dynamodb';
import { ebsChecks } from './ebs';
import { ec2Checks } from './ec2';
import { ecrChecks } from './ecr';
import { ecsChecks } from './ecs';
import { efsChecks } from './efs';
import { eksChecks } from './eks';
import { elasticacheChecks } from './elasticache';
import { elasticbeanstalkChecks } from './elasticbeanstalk';
import { elbChecks } from './elb';
import { emrChecks } from './emr';
import { eventbridgeChecks } from './eventbridge';
import { firehoseChecks } from './firehose';
import { fmsChecks } from './fms';
import { fsxChecks } from './fsx';
import { glacierChecks } from './glacier';
import { glueChecks } from './glue';
import { iamChecks } from './iam';
import { inspector2Checks } from './inspector2';
import { kafkaChecks } from './kafka';
import { kinesisChecks } from './kinesis';
import { kmsChecks } from './kms';
import { lambdaChecks } from './lambda';
import { lightsailChecks } from './lightsail';
import { macieChecks } from './macie';
import { memorydbChecks } from './memorydb';
import { mqChecks } from './mq';
import { neptuneChecks } from './neptune';
import { networkfirewallChecks } from './networkfirewall';
import { opensearchChecks } from './opensearch';
import { organizationsChecks } from './organizations';
import { rdsChecks } from './rds';
import { redshiftChecks } from './redshift';
import { resourceexplorer2Checks } from './resourceexplorer2';
import { rolesanywhereChecks } from './rolesanywhere';
import { route53Checks } from './route53';
import { s3Checks } from './s3';
import { sagemakerChecks } from './sagemaker';
import { secretsmanagerChecks } from './secretsmanager';
import { securityhubChecks } from './securityhub';
import { servicecatalogChecks } from './servicecatalog';
import { sesChecks } from './ses';
import { shieldChecks } from './shield';
import { snsChecks } from './sns';
import { sqsChecks } from './sqs';
import { ssmChecks } from './ssm';
import { ssmincidentsChecks } from './ssmincidents';
import { stepfunctionsChecks } from './stepfunctions';
import { storagegatewayChecks } from './storagegateway';
import { threatdetectionChecks } from './threatdetection';
import { transferChecks } from './transfer';
import { trustedadvisorChecks } from './trustedadvisor';
import { vpcChecks } from './vpc';
import { wafChecks } from './waf';
import { wellarchitectedChecks } from './wellarchitected';
import { workspacesChecks } from './workspaces';

export const awsChecks: CheckMetadata[] = [
  ...accessanalyzerChecks,
  ...accountChecks,
  ...acmChecks,
  ...acmpcaChecks,
  ...amplifyChecks,
  ...apigatewayChecks,
  ...apigatewayv2Checks,
  ...appstreamChecks,
  ...appsyncChecks,
  ...athenaChecks,
  ...autoscalingChecks,
  ...backupChecks,
  ...bedrockChecks,
  ...cloudformationChecks,
  ...cloudfrontChecks,
  ...cloudtrailChecks,
  ...cloudwatchChecks,
  ...codeartifactChecks,
  ...codebuildChecks,
  ...codecommitChecks,
  ...codepipelineChecks,
  ...cognitoChecks,
  ...configChecks,
  ...datapipelineChecks,
  ...datasyncChecks,
  ...directconnectChecks,
  ...directoryserviceChecks,
  ...dlmChecks,
  ...dmsChecks,
  ...documentdbChecks,
  ...drsChecks,
  ...dynamodbChecks,
  ...ebsChecks,
  ...ec2Checks,
  ...ecrChecks,
  ...ecsChecks,
  ...efsChecks,
  ...eksChecks,
  ...elasticacheChecks,
  ...elasticbeanstalkChecks,
  ...elbChecks,
  ...emrChecks,
  ...eventbridgeChecks,
  ...firehoseChecks,
  ...fmsChecks,
  ...fsxChecks,
  ...glacierChecks,
  ...glueChecks,
  ...iamChecks,
  ...inspector2Checks,
  ...kafkaChecks,
  ...kinesisChecks,
  ...kmsChecks,
  ...lambdaChecks,
  ...lightsailChecks,
  ...macieChecks,
  ...memorydbChecks,
  ...mqChecks,
  ...neptuneChecks,
  ...networkfirewallChecks,
  ...opensearchChecks,
  ...organizationsChecks,
  ...rdsChecks,
  ...redshiftChecks,
  ...resourceexplorer2Checks,
  ...rolesanywhereChecks,
  ...route53Checks,
  ...s3Checks,
  ...sagemakerChecks,
  ...secretsmanagerChecks,
  ...securityhubChecks,
  ...servicecatalogChecks,
  ...sesChecks,
  ...shieldChecks,
  ...snsChecks,
  ...sqsChecks,
  ...ssmChecks,
  ...ssmincidentsChecks,
  ...stepfunctionsChecks,
  ...storagegatewayChecks,
  ...threatdetectionChecks,
  ...transferChecks,
  ...trustedadvisorChecks,
  ...vpcChecks,
  ...wafChecks,
  ...wellarchitectedChecks,
  ...workspacesChecks,
];
