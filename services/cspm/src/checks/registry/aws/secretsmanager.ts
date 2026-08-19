import { CheckMetadata } from '../../types';

// Titles must stay byte-identical to the pre-registry hardcoded titles:
// the scan worker dedupes OPEN findings on service:title:fingerprint, so a
// reworded title would re-open every existing finding as "new".
export const secretsmanagerChecks: CheckMetadata[] = [
  {
    checkId: 'secretsmanager_secret_scheduled_for_deletion',
    provider: 'aws',
    service: 'secretsmanager',
    title: 'Secret Scheduled for Deletion',
    severity: 'MEDIUM',
    description: 'Checks for Secrets Manager secrets that are scheduled for deletion.',
    remediation: 'Restore or remove the scheduled deletion if secret is still needed',
    tags: ['secrets-manager', 'secret-management'],
  },
  {
    checkId: 'secretsmanager_automatic_rotation_enabled',
    provider: 'aws',
    service: 'secretsmanager',
    title: 'Secret Rotation Not Enabled',
    severity: 'MEDIUM',
    description: 'Checks that Secrets Manager secrets have automatic rotation enabled.',
    remediation: 'Enable automatic rotation for the secret using a rotation Lambda function.',
    tags: ['secrets-manager', 'secret-rotation', 'compliance'],
  },
  {
    checkId: 'secretsmanager_secret_encrypted_with_cmk',
    provider: 'aws',
    service: 'secretsmanager',
    title: 'Secret Using Default Encryption',
    severity: 'LOW',
    description: 'Checks that Secrets Manager secrets are encrypted with a customer-managed KMS key rather than the default encryption key.',
    remediation: 'Encrypt the secret with a customer-managed KMS key instead of the default aws/secretsmanager key.',
    tags: ['secrets-manager', 'encryption', 'kms'],
  },
  {
    checkId: 'secretsmanager_secret_cross_region_replication',
    provider: 'aws',
    service: 'secretsmanager',
    title: 'Secret Not Replicated',
    severity: 'LOW',
    description: 'Checks that Secrets Manager secrets are replicated to another region for disaster recovery.',
    remediation: 'Replicate the secret to another region for disaster recovery.',
    tags: ['secrets-manager', 'disaster-recovery', 'high-availability'],
  },
];
