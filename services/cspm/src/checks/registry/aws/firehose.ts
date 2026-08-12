// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const firehoseChecks: CheckMetadata[] = [
  {
    checkId: 'firehose_stream_encrypted_at_rest',
    provider: 'aws',
    service: 'firehose',
    title: 'Firehose Stream Not Encrypted At Rest',
    severity: 'MEDIUM',
    description: 'Checks that Data Firehose delivery streams have server-side encryption at rest enabled with an AWS KMS key.',
    remediation: 'Enable server-side encryption (StartDeliveryStreamEncryption) on Direct PUT delivery streams using an AWS-owned or customer-managed KMS key; for Kinesis-sourced streams enable SSE on the source Kinesis data stream.',
    tags: ['firehose', 'encryption', 'kms'],
  },
];
