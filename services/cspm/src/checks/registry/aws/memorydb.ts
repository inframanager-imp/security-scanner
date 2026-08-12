// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const memorydbChecks: CheckMetadata[] = [
  {
    checkId: 'memorydb_cluster_auto_minor_version_upgrades',
    provider: 'aws',
    service: 'memorydb',
    title: 'MemoryDB Cluster Auto Minor Version Upgrade Disabled',
    severity: 'MEDIUM',
    description: 'Checks that the MemoryDB cluster has automatic minor version upgrades enabled so engine security patches are applied promptly.',
    remediation: 'Enable automatic minor version upgrades on the cluster, schedule updates in a maintenance window, and validate changes in staging with a rollback plan.',
    tags: ['memorydb', 'patching', 'version'],
  },
];
