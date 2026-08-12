import { CheckMetadata } from '../../types';

// Titles must stay byte-identical to the pre-registry hardcoded titles:
// the scan worker dedupes OPEN findings on service:title:fingerprint, so a
// reworded title would re-open every existing finding as "new".
export const sqsChecks: CheckMetadata[] = [
  {
    checkId: 'sqs_queues_not_publicly_accessible',
    provider: 'aws',
    service: 'sqs',
    title: 'SQS Queue Allows Public Access',
    severity: 'CRITICAL',
    description: 'Checks that SQS queue policies do not grant access to all principals ("*"), which would let any AWS account send to or receive from the queue.',
    remediation: 'Update the SQS queue policy to restrict the Principal to specific AWS accounts or IAM roles. Remove any Statement with Principal: "*".',
    tags: ['sqs', 'access-control'],
  },
  {
    checkId: 'sqs_queues_server_side_encryption_enabled',
    provider: 'aws',
    service: 'sqs',
    title: 'SQS Queue Not Encrypted',
    severity: 'MEDIUM',
    description: 'Checks that SQS queues have server-side encryption enabled so stored messages do not expose sensitive data.',
    remediation: 'Enable SSE: aws sqs set-queue-attributes --queue-url <queue-url> --attributes KmsMasterKeyId=alias/aws/sqs',
    tags: ['sqs', 'encryption'],
  },
  {
    checkId: 'sqs_queue_dead_letter_queue_configured',
    provider: 'aws',
    service: 'sqs',
    title: 'SQS Queue Has No Dead-Letter Queue',
    severity: 'LOW',
    description: 'Checks that SQS queues have a dead-letter queue (DLQ) configured; without one, failed messages are retried indefinitely and eventually lost, making failures invisible.',
    remediation: 'Configure a DLQ: create a separate SQS queue and set it as the RedrivePolicy target with a maxReceiveCount of 3-5.',
    tags: ['sqs', 'reliability'],
  },
];
