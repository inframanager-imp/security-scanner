// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const configChecks: CheckMetadata[] = [
  {
    checkId: 'config_delegated_admin_and_org_aggregator_all_regions',
    provider: 'aws',
    service: 'config',
    title: 'Config Organization Aggregator Not Covering All Regions',
    severity: 'HIGH',
    description: 'Checks that AWS Config has a delegated administrator registered for config.amazonaws.com and that configuration aggregators use an organization aggregation source covering all AWS Regions.',
    remediation: 'Register a delegated administrator for config.amazonaws.com via AWS Organizations and create an organization configuration aggregator with AllAwsRegions enabled.',
    tags: ['config', 'organizations', 'aggregator'],
  },
  {
    checkId: 'config_recorder_using_aws_service_role',
    provider: 'aws',
    service: 'config',
    title: 'Config Recorder Not Using Service-Linked Role',
    severity: 'MEDIUM',
    description: 'Checks that active AWS Config configuration recorders use the AWSServiceRoleForConfig service-linked role instead of a custom IAM role, ensuring least-privilege permissions managed by AWS.',
    remediation: 'Create the service-linked role (aws iam create-service-linked-role --aws-service-name config.amazonaws.com) and update the configuration recorder to use AWSServiceRoleForConfig.',
    tags: ['config', 'iam', 'service-linked-role'],
  },
];
