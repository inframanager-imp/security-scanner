import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class GcpStorageScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-Storage');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      const storage = this.client.storage();
      const res = await storage.buckets.list({
        project,
        projection: 'full',
        maxResults: 1000,
      });
      const buckets = res.data.items ?? [];

      if (buckets.length === 0) return findings;

      for (const bucket of buckets) {
        const name = bucket.name ?? 'unknown';

        // 1. Public access — allUsers or allAuthenticatedUsers in IAM
        try {
          const iamRes = await storage.buckets.getIamPolicy({ bucket: name });
          const bindings = iamRes.data.bindings ?? [];
          const publicBindings = bindings.filter(b =>
            (b.members ?? []).some(m => m === 'allUsers' || m === 'allAuthenticatedUsers'),
          );
          if (publicBindings.length > 0) {
            const roles = publicBindings.map(b => b.role).join(', ');
            findings.push(this.finding(
              'Cloud Storage bucket is publicly accessible',
              `Bucket "${name}" has IAM bindings granting access to allUsers or allAuthenticatedUsers with roles: ${roles}. Any internet user can read or write objects in this bucket.`,
              'CRITICAL',
              { bucket: name, publicRoles: roles, project },
              'Remove allUsers and allAuthenticatedUsers from all bucket IAM bindings. Enable "Prevent Public Access" at the project level via Public Access Prevention.',
              ['storage', 'public-access'],
            ));
          }
        } catch { /* IAM check optional */ }

        // 2. Uniform bucket-level access disabled
        if (!bucket.iamConfiguration?.uniformBucketLevelAccess?.enabled) {
          findings.push(this.finding(
            'Cloud Storage bucket has uniform bucket-level access disabled',
            `Bucket "${name}" uses per-object ACLs in addition to IAM policies. Object ACLs are a legacy access control mechanism that can inadvertently grant public access to individual objects even when the bucket IAM is restrictive.`,
            'HIGH',
            { bucket: name, project },
            'Enable uniform bucket-level access on the bucket. This disables legacy ACLs and ensures only IAM policies control access, making the permission model simpler and auditable.',
            ['storage', 'access-control'],
          ));
        }

        // 3. Public Access Prevention not enforced
        const pap = bucket.iamConfiguration?.publicAccessPrevention;
        if (pap !== 'enforced') {
          findings.push(this.finding(
            'Cloud Storage bucket does not enforce Public Access Prevention',
            `Bucket "${name}" has Public Access Prevention set to "${pap ?? 'inherited'}". Without enforcement, future IAM policy changes could inadvertently expose the bucket publicly.`,
            'MEDIUM',
            { bucket: name, publicAccessPrevention: pap ?? 'inherited', project },
            'Set Public Access Prevention to "enforced" on the bucket to permanently block any IAM bindings that would grant public access.',
            ['storage', 'public-access'],
          ));
        }

        // 4. No CMEK (customer-managed encryption key)
        if (!bucket.encryption?.defaultKmsKeyName) {
          findings.push(this.finding(
            'Cloud Storage bucket does not use a customer-managed encryption key',
            `Bucket "${name}" uses Google-managed encryption keys. Customer-managed keys (CMEK) via Cloud KMS give you control over key lifecycle, rotation, and the ability to revoke access to stored data.`,
            'MEDIUM',
            { bucket: name, project },
            'Configure a Cloud KMS key as the default encryption key for the bucket. Assign the Cloud KMS CryptoKey Encrypter/Decrypter role to the Cloud Storage service account.',
            ['storage', 'encryption', 'cmek'],
          ));
        }

        // 5. Versioning not enabled
        if (!bucket.versioning?.enabled) {
          findings.push(this.finding(
            'Cloud Storage bucket has versioning disabled',
            `Bucket "${name}" does not have object versioning enabled. Without versioning, objects deleted or overwritten by ransomware or accidental operations cannot be recovered.`,
            'MEDIUM',
            { bucket: name, project },
            'Enable object versioning on the bucket. Configure Object Lifecycle Management to automatically delete old versions after a retention period to control storage costs.',
            ['storage', 'versioning', 'data-protection'],
          ));
        }

        // 6. Access logs not configured
        if (!bucket.logging?.logBucket) {
          findings.push(this.finding(
            'Cloud Storage bucket has access logging disabled',
            `Bucket "${name}" does not log access requests. Without access logs, you cannot detect unauthorized data access, enumerate who accessed which objects, or investigate data exfiltration incidents.`,
            'MEDIUM',
            { bucket: name, project },
            'Enable access logging on the bucket by specifying a log bucket. Ensure the log bucket itself has appropriate access controls and retention policies.',
            ['storage', 'logging', 'audit'],
          ));
        }

        // 7. Retention policy not configured
        if (!bucket.retentionPolicy) {
          findings.push(this.finding(
            'Cloud Storage bucket has no retention policy configured',
            `Bucket "${name}" has no retention policy. Objects can be deleted before required retention periods for compliance (SOC 2, HIPAA, PCI-DSS) are satisfied.`,
            'LOW',
            { bucket: name, project },
            'Set a retention policy on the bucket matching your compliance requirements. Lock the policy to make it immutable for regulatory compliance.',
            ['storage', 'compliance', 'retention'],
          ));
        }

        // 8. Requester pays enabled — billing exposure
        if (bucket.billing?.requesterPays) {
          findings.push(this.finding(
            'Cloud Storage bucket has Requester Pays enabled',
            `Bucket "${name}" has Requester Pays enabled. While this moves bandwidth costs to requesters, it can be abused if authentication is misconfigured — requesters may access data without your knowledge.`,
            'LOW',
            { bucket: name, project },
            'Review whether Requester Pays is necessary. If not, disable it. Ensure bucket IAM policies are tightly controlled when using this feature.',
            ['storage', 'billing'],
          ));
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'GCP Cloud Storage scan error',
        `Could not complete Cloud Storage scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service account has roles/storage.admin or roles/iam.securityReviewer on the project.',
      ));
    }

    return findings;
  }
}
