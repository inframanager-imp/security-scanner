import { CheckMetadata } from '../../types';

// Titles must stay byte-identical to the pre-registry hardcoded titles:
// the scan worker dedupes OPEN findings on service:title:fingerprint, so a
// reworded title would re-open every existing finding as "new".
export const kmsChecks: CheckMetadata[] = [
  {
    checkId: 'kms_cmk_not_deleted_unintentionally',
    provider: 'aws',
    service: 'kms',
    title: 'KMS Key Pending Deletion',
    severity: 'MEDIUM',
    description: 'Checks for KMS keys scheduled for deletion; deletion is irreversible and data encrypted under the key becomes unrecoverable.',
    remediation: "Cancel deletion or let the key expire if it's no longer needed",
    tags: ['kms', 'key-management'],
  },
  {
    checkId: 'kms_cmk_are_used',
    provider: 'aws',
    service: 'kms',
    title: 'KMS Key Disabled',
    severity: 'MEDIUM',
    description: 'Checks for KMS keys that are disabled; disabled keys cannot be used and may indicate stale key management.',
    remediation: "Enable the KMS key if it's still needed, or schedule it for deletion if not.",
    tags: ['kms', 'key-management'],
  },
  {
    checkId: 'kms_cmk_rotation_enabled',
    provider: 'aws',
    service: 'kms',
    title: 'KMS Key Rotation Not Enabled',
    severity: 'MEDIUM',
    description: 'Checks that customer-managed KMS keys have automatic key rotation enabled.',
    remediation: 'Enable automatic key rotation for the customer-managed KMS key.',
    tags: ['kms', 'key-rotation', 'compliance'],
  },
];
