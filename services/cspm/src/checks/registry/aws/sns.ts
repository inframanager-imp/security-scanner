// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

// Titles must stay byte-identical to the pre-registry hardcoded titles:
// the scan worker dedupes OPEN findings on service:title:fingerprint, so a
// reworded title would re-open every existing finding as "new".
export const snsChecks: CheckMetadata[] = [
  {
    checkId: 'sns_topics_not_publicly_accessible',
    provider: 'aws',
    service: 'sns',
    title: 'SNS Topic Allows Public Access',
    severity: 'CRITICAL',
    description: 'Checks that SNS topic resource policies do not grant access to all principals ("*"), which would let any AWS account or unauthenticated user publish or subscribe to the topic.',
    remediation: 'Update the SNS topic policy to restrict the Principal to specific AWS accounts or IAM roles only. Remove any Statement with Principal: "*".',
    tags: ['sns', 'access-control'],
  },
  {
    checkId: 'sns_topics_kms_encryption_at_rest_enabled',
    provider: 'aws',
    service: 'sns',
    title: 'SNS Topic Not Encrypted With KMS',
    severity: 'MEDIUM',
    description: 'Checks that SNS topics have server-side encryption (SSE) enabled so messages stored in the topic are encrypted at rest.',
    remediation: 'Enable SSE: aws sns set-topic-attributes --topic-arn <topic-arn> --attribute-name KmsMasterKeyId --attribute-value alias/aws/sns',
    tags: ['sns', 'encryption'],
  },
  {
    checkId: 'sns_subscription_not_using_http_endpoints',
    provider: 'aws',
    service: 'sns',
    title: 'SNS Subscription Using HTTP Endpoint',
    severity: 'HIGH',
    description: 'Checks that confirmed SNS subscriptions do not deliver to plain HTTP endpoints; unencrypted deliveries can be eavesdropped or tampered with in transit.',
    remediation: 'Delete the HTTP subscription and re-create it with Protocol=https pointing at an HTTPS endpoint; verify SNS message signatures at the receiver and enforce TLS with aws:SecureTransport conditions.',
    tags: ['sns', 'encryption', 'in-transit'],
  },
];
