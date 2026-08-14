// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const dataprocChecks: CheckMetadata[] = [
  {
    checkId: 'dataproc_encrypted_with_cmks_disabled',
    provider: 'gcp',
    service: 'dataproc',
    title: 'Dataproc Cluster Is Encrypted With A Customer-Managed Encryption Key',
    severity: 'MEDIUM',
    description: 'Checks that each Dataproc cluster has a customer-managed encryption key (CMEK) configured for VM persistent disk encryption, instead of relying solely on Google-managed keys.',
    remediation: 'Recreate the cluster with a Cloud KMS key set as the disk encryption key (gcePdKmsKeyName in the cluster encryption config), grant the Dataproc service account the required KMS permissions, and migrate workloads to the new cluster.',
    tags: ['dataproc', 'encryption', 'cmek'],
  },
];
