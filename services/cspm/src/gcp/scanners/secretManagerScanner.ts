import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class GcpSecretManagerScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-SecretManager');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      const sm  = this.client.secretmanager();
      const res = await sm.projects.secrets.list({
        parent: `projects/${project}`,
        pageSize: 300,
      });
      const secrets = res.data.secrets ?? [];

      if (secrets.length === 0) return findings;

      for (const secret of secrets) {
        const secretName = secret.name?.split('/').pop() ?? 'unknown';

        // 1. No CMEK
        if (!secret.replication?.userManaged && !secret.customerManagedEncryption?.kmsKeyName) {
          const isAutoReplicated = !!secret.replication?.automatic;
          if (isAutoReplicated && !secret.replication?.automatic?.customerManagedEncryption?.kmsKeyName) {
            findings.push(this.finding(
              'Secret Manager secret does not use a customer-managed encryption key',
              `Secret "${secretName}" in project "${project}" uses Google-managed encryption. CMEK gives control over key lifecycle and allows revoking access to secret data by disabling or destroying the KMS key.`,
              'MEDIUM',
              { secret: secretName, project },
              'Configure a Cloud KMS key for encryption on the secret. This requires the Secret Manager service account to have Cloud KMS encrypter/decrypter permissions.',
              ['secretmanager', 'encryption', 'cmek'],
            ));
          }
        }

        // 2. Automatic replication (data in all regions — may violate data residency)
        if (secret.replication?.automatic) {
          findings.push(this.finding(
            'Secret Manager secret uses automatic (global) replication',
            `Secret "${secretName}" uses automatic replication, which stores the secret in all Google Cloud regions worldwide. This may violate data residency or compliance requirements for specific regulations (GDPR, etc.).`,
            'LOW',
            { secret: secretName, project, replication: 'automatic' },
            'If data residency is required, migrate the secret to user-managed replication and specify only the allowed regions.',
            ['secretmanager', 'data-residency'],
          ));
        }

        // 3. Secret has no versions (empty secret)
        try {
          const verRes = await sm.projects.secrets.versions.list({
            parent: secret.name!,
            pageSize: 1,
          });
          const versions = verRes.data.versions ?? [];
          if (versions.length === 0) {
            findings.push(this.finding(
              'Secret Manager secret has no versions (empty secret)',
              `Secret "${secretName}" in project "${project}" has no secret versions. Empty secrets may indicate orphaned resources or incomplete setup.`,
              'LOW',
              { secret: secretName, project },
              'Delete secrets that are not in use. Ensure active secrets have at least one enabled version.',
              ['secretmanager', 'lifecycle'],
            ));
          }

          // 4. Secret not rotated in 365 days
          if (versions.length > 0) {
            const latestVer = versions[0];
            const createTime = latestVer.createTime ? new Date(latestVer.createTime) : null;
            if (createTime) {
              const ageDays = (Date.now() - createTime.getTime()) / (1000 * 60 * 60 * 24);
              if (ageDays > 365) {
                findings.push(this.finding(
                  'Secret Manager secret has not been rotated in over 365 days',
                  `Secret "${secretName}" in project "${project}" has the latest version created ${Math.round(ageDays)} days ago. Long-lived secrets are more likely to be exposed through logs, compromised systems, or insider threats.`,
                  'MEDIUM',
                  { secret: secretName, project, ageDays: Math.round(ageDays) },
                  'Rotate the secret by creating a new version with updated credentials. Configure rotation notifications via Pub/Sub to trigger automated rotation workflows.',
                  ['secretmanager', 'rotation'],
                ));
              }
            }
          }
        } catch { /* version check optional */ }

        // 5. IAM — check for public access
        try {
          const iamRes = await sm.projects.secrets.getIamPolicy({ resource: secret.name! });
          const bindings = iamRes.data.bindings ?? [];
          const publicBinding = bindings.find(b =>
            (b.members ?? []).some(m => m === 'allUsers' || m === 'allAuthenticatedUsers'),
          );
          if (publicBinding) {
            findings.push(this.finding(
              'Secret Manager secret is publicly accessible',
              `Secret "${secretName}" in project "${project}" has a public IAM binding with role "${publicBinding.role}". Any internet user can access the secret value.`,
              'CRITICAL',
              { secret: secretName, project, publicRole: publicBinding.role },
              'Immediately remove allUsers and allAuthenticatedUsers from the secret IAM policy.',
              ['secretmanager', 'public-access'],
            ));
          }
        } catch { /* optional */ }
      }
    } catch (err) {
      findings.push(this.finding(
        'GCP Secret Manager scan error',
        `Could not complete Secret Manager scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service account has roles/secretmanager.viewer on the project.',
      ));
    }

    return findings;
  }
}
