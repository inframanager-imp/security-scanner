import { CheckMetadata } from '../../types';

// Titles must stay byte-identical to the pre-registry hardcoded titles:
// the scan worker dedupes OPEN findings on service:title:fingerprint, so a
// reworded title would re-open every existing finding as "new".
export const ebsChecks: CheckMetadata[] = [
  {
    checkId: 'ebs_default_encryption_aws_managed_key',
    provider: 'aws',
    service: 'ebs',
    title: 'EBS Default Encryption Uses AWS-Managed Key',
    severity: 'LOW',
    description: 'Checks that the default EBS encryption key is a customer-managed KMS key rather than the AWS-managed key (alias/aws/ebs), which cannot be audited, rotated on a custom schedule, or scoped with a key policy.',
    remediation: 'Switch the default EBS KMS key to a customer-managed key: aws ec2 modify-ebs-default-kms-key-id --kms-key-id <your-cmk-arn>',
    tags: ['ebs', 'encryption', 'kms', 'cmk'],
  },
  {
    checkId: 'ebs_default_encryption_disabled',
    provider: 'aws',
    service: 'ebs',
    title: 'EBS Default Encryption Disabled',
    severity: 'HIGH',
    description: 'Checks that EBS encryption by default is enabled for the region so new EBS volumes and snapshot copies are automatically encrypted.',
    remediation: 'Enable EBS default encryption: aws ec2 enable-ebs-encryption-by-default',
    tags: ['ebs', 'encryption'],
  },
  {
    checkId: 'ec2_ebs_volume_encryption',
    provider: 'aws',
    service: 'ebs',
    title: 'Unencrypted EBS Volume Attached to Instance',
    severity: 'HIGH',
    description: 'Checks for unencrypted EBS volumes attached to instances, which expose data at rest.',
    remediation: 'Create encrypted snapshots and replace volumes. Enable EBS default encryption to prevent future unencrypted volumes.',
    tags: ['ebs', 'encryption'],
  },
  {
    checkId: 'ec2_ebs_public_snapshot',
    provider: 'aws',
    service: 'ebs',
    title: 'EBS Snapshot Publicly Accessible',
    severity: 'CRITICAL',
    description: 'Checks for EBS snapshots that are publicly accessible, allowing any AWS account to copy them and access all data they contain.',
    remediation: 'Make the snapshot private immediately: aws ec2 modify-snapshot-attribute --snapshot-id <snapshot-id> --attribute createVolumePermission --operation-type remove --group-names all',
    tags: ['ebs', 'snapshot', 'public'],
  },
  {
    checkId: 'ec2_ebs_snapshots_encrypted',
    provider: 'aws',
    service: 'ebs',
    title: 'Unencrypted EBS Snapshots',
    severity: 'MEDIUM',
    description: 'Checks for unencrypted EBS snapshots, which expose backup data and can be copied by other accounts if made public.',
    remediation: 'Copy existing snapshots with encryption enabled. Enable EBS default encryption to encrypt all future snapshots.',
    tags: ['ebs', 'snapshot', 'encryption'],
  },
];
