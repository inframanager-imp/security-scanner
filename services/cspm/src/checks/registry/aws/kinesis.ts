// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
// kinesis_stream_encrypted_with_cmk and kinesis_stream_enhanced_monitoring_enabled are
// supplemental best-practice checks (no Prowler equivalent); their IDs are coined here.
import { CheckMetadata } from '../../types';

export const kinesisChecks: CheckMetadata[] = [
  {
    checkId: 'kinesis_stream_encrypted_at_rest',
    provider: 'aws',
    service: 'kinesis',
    title: 'Kinesis Stream Not Encrypted At Rest',
    severity: 'HIGH',
    description: 'Checks that Kinesis Data Streams have server-side encryption (SSE-KMS) configured so records are protected at rest.',
    remediation: 'Enable SSE-KMS on the stream, prefer customer-managed keys for rotation and ownership, and enforce least privilege on KMS grants.',
    tags: ['kinesis', 'encryption', 'kms'],
  },
  {
    checkId: 'kinesis_stream_encrypted_with_cmk',
    provider: 'aws',
    service: 'kinesis',
    title: 'Kinesis Stream Not Using Customer Managed Key',
    severity: 'MEDIUM',
    description: 'Checks that KMS-encrypted Kinesis streams use a customer-managed KMS key rather than the AWS-managed alias/aws/kinesis key, which offers no key policy control or rotation ownership.',
    remediation: 'Re-encrypt the stream with a customer-managed KMS key (StartStreamEncryption with your CMK), apply least-privilege key policies and enable rotation.',
    tags: ['kinesis', 'encryption', 'kms'],
  },
  {
    checkId: 'kinesis_stream_data_retention_period',
    provider: 'aws',
    service: 'kinesis',
    title: 'Kinesis Stream Retention Below 168 Hours',
    severity: 'MEDIUM',
    description: 'Checks that Kinesis streams retain records for at least 168 hours (7 days) so data can be replayed after consumer lag or failure.',
    remediation: 'Increase the stream retention period to at least 168 hours (or your compliance window) to cover worst-case consumer lag and replay needs, and maintain secondary archival for critical streams.',
    tags: ['kinesis', 'retention', 'data-protection'],
  },
  {
    checkId: 'kinesis_stream_enhanced_monitoring_enabled',
    provider: 'aws',
    service: 'kinesis',
    title: 'Kinesis Enhanced Monitoring Disabled',
    severity: 'LOW',
    description: 'Checks that Kinesis streams have enhanced (shard-level) CloudWatch monitoring enabled so per-shard metrics can reveal hot shards and abnormal consumption patterns.',
    remediation: 'Enable shard-level metrics on the stream (EnableEnhancedMonitoring) for the metrics you need, and alert on anomalies in per-shard throughput.',
    tags: ['kinesis', 'monitoring', 'observability'],
  },
];
