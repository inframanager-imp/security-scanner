// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const cloudformationChecks: CheckMetadata[] = [
  {
    checkId: 'cloudformation_stack_outputs_find_secrets',
    provider: 'aws',
    service: 'cloudformation',
    title: 'CloudFormation Stack Outputs Contain Secrets',
    severity: 'CRITICAL',
    description: 'Checks CloudFormation stack Outputs for hardcoded secrets such as passwords, API keys and tokens, which are readable by anyone with stack metadata access.',
    remediation: 'Remove secrets from stack Outputs. Store credentials in Secrets Manager or SSM Parameter Store and reference them via dynamic references; use NoEcho for sensitive parameters and avoid exporting sensitive values.',
    tags: ['cloudformation', 'secrets', 'outputs'],
  },
  {
    checkId: 'cloudformation_stack_cdktoolkit_bootstrap_version',
    provider: 'aws',
    service: 'cloudformation',
    title: 'CDK Bootstrap Stack Version Outdated',
    severity: 'HIGH',
    description: 'Checks that the CDKToolkit CloudFormation stack reports a BootstrapVersion of 21 or higher; older bootstrap stacks lack recent hardening of asset buckets and deployment roles.',
    remediation: 'Re-bootstrap the environment with a modern CDK version (cdk bootstrap) so BootstrapVersion is at least 21, apply least privilege to bootstrap roles and limit trusted accounts.',
    tags: ['cloudformation', 'cdk', 'bootstrap', 'patching'],
  },
  {
    checkId: 'cloudformation_stacks_termination_protection_enabled',
    provider: 'aws',
    service: 'cloudformation',
    title: 'CloudFormation Stack Termination Protection Disabled',
    severity: 'MEDIUM',
    description: 'Checks that non-nested CloudFormation stacks have termination protection enabled to block accidental or malicious stack deletion.',
    remediation: 'Enable termination protection on root stacks for critical workloads, restrict who can alter the setting, and use stack policies plus DeletionPolicy: Retain for data stores.',
    tags: ['cloudformation', 'termination-protection', 'resilience'],
  },
];
