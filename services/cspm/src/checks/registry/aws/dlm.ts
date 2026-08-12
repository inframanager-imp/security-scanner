// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const dlmChecks: CheckMetadata[] = [
  {
    checkId: 'dlm_ebs_snapshot_lifecycle_policy_exists',
    provider: 'aws',
    service: 'dlm',
    title: 'EBS Snapshots Without DLM Lifecycle Policy',
    severity: 'MEDIUM',
    description: 'Checks that regions containing self-owned EBS snapshots have at least one Data Lifecycle Manager (DLM) lifecycle policy to automate snapshot creation, retention and cleanup.',
    remediation: 'Create DLM lifecycle policies for volumes that require backup: schedule snapshot creation to meet RPO/RTO, define retention rules to prevent sprawl, use least-privilege execution roles, and copy snapshots to another region or account for resilience.',
    tags: ['dlm', 'ebs', 'backup', 'resilience'],
  },
];
