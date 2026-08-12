// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const stepfunctionsChecks: CheckMetadata[] = [
  {
    checkId: 'stepfunctions_statemachine_encrypted_with_cmk',
    provider: 'aws',
    service: 'stepfunctions',
    title: 'Step Functions State Machine Not Using Customer-Managed KMS Key',
    severity: 'MEDIUM',
    description: 'Checks that Step Functions state machines are encrypted at rest with a customer-managed KMS key (CUSTOMER_MANAGED_KMS_KEY) rather than the default AWS-owned key, which cannot be controlled, rotated or revoked by the account.',
    remediation: 'Configure the state machine with a customer-managed KMS key for encryption at rest, apply least-privilege key policies, and enable key rotation and CloudTrail auditing of key usage.',
    tags: ['stepfunctions', 'encryption', 'kms'],
  },
  {
    checkId: 'stepfunctions_statemachine_logging_enabled',
    provider: 'aws',
    service: 'stepfunctions',
    title: 'Step Functions State Machine Logging Disabled',
    severity: 'MEDIUM',
    description: 'Checks that Step Functions state machines have execution logging to CloudWatch Logs configured with a log level above OFF; without execution logs, workflow failures and misuse go undetected and forensics are impossible.',
    remediation: 'Set the state machine logging configuration to level ALL or ERROR with a CloudWatch Logs destination, and grant the execution role permission to deliver logs.',
    tags: ['stepfunctions', 'logging', 'audit'],
  },
  {
    checkId: 'stepfunctions_statemachine_no_secrets_in_definition',
    provider: 'aws',
    service: 'stepfunctions',
    title: 'Step Functions Definition Contains Hardcoded Secrets',
    severity: 'CRITICAL',
    description: 'Checks Step Functions state machine definitions (Amazon States Language JSON) for hardcoded credentials such as keys, tokens or passwords; these are visible in the console/CLI and can leak into execution logs.',
    remediation: 'Remove plaintext credentials from the state machine definition; store them in AWS Secrets Manager or SSM Parameter Store and resolve them at runtime from the invoked task instead.',
    tags: ['stepfunctions', 'secrets', 'credentials'],
  },
];
