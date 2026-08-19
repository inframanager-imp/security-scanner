import { CheckMetadata } from '../../types';

// Titles must stay byte-identical to the pre-registry hardcoded titles:
// the scan worker dedupes OPEN findings on service:title:fingerprint, so a
// reworded title would re-open every existing finding as "new".
export const dynamodbChecks: CheckMetadata[] = [
  {
    checkId: 'dynamodb_tables_kms_cmk_encryption_enabled',
    provider: 'aws',
    service: 'dynamodb',
    title: 'DynamoDB Table Not Encrypted With CMK',
    severity: 'MEDIUM',
    description: 'Checks that DynamoDB tables are encrypted with a customer-managed KMS key rather than being unencrypted or using only AWS-owned keys, which cannot be audited or rotated by you.',
    remediation: 'Enable CMK encryption: aws dynamodb update-table --table-name <table-name> --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=<your-key-arn>',
    tags: ['dynamodb', 'encryption'],
  },
  {
    checkId: 'dynamodb_tables_pitr_enabled',
    provider: 'aws',
    service: 'dynamodb',
    title: 'DynamoDB Table Point-in-Time Recovery Disabled',
    severity: 'HIGH',
    description: 'Checks that DynamoDB tables have Point-in-Time Recovery (PITR) enabled so accidental deletes or corruption can be recovered within a 35-day window.',
    remediation: 'Enable PITR: aws dynamodb update-continuous-backups --table-name <table-name> --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true',
    tags: ['dynamodb', 'backup', 'recovery'],
  },
  {
    checkId: 'dynamodb_table_deletion_protection_enabled',
    provider: 'aws',
    service: 'dynamodb',
    title: 'DynamoDB Table Deletion Protection Disabled',
    severity: 'MEDIUM',
    description: 'Checks that DynamoDB tables have deletion protection enabled so they cannot be deleted accidentally or by a compromised credential.',
    remediation: 'Enable deletion protection: aws dynamodb update-table --table-name <table-name> --deletion-protection-enabled',
    tags: ['dynamodb', 'availability'],
  },
  {
    checkId: 'dynamodb_table_replica_autoscaling_enabled',
    provider: 'aws',
    service: 'dynamodb',
    title: 'DynamoDB Global Table Replica Missing Auto Scaling',
    severity: 'LOW',
    description: 'Checks that DynamoDB global table replicas have autoscaling configured; without it, replicas can be throttled under load or over-provisioned (cost).',
    remediation: 'Enable autoscaling on each replica via the DynamoDB console under Additional settings > Auto scaling.',
    tags: ['dynamodb', 'availability', 'global-tables'],
  },
];
