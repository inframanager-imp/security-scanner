import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const MAX_ROTATION_DAYS = 90;

export class GcpKMSScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-KMS');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      const kms = this.client.cloudkms();

      // List all key rings across all locations
      const locRes = await kms.projects.locations.list({ name: `projects/${project}` });
      const locations = (locRes.data.locations ?? []).map((l: any) => l.locationId ?? l.name?.split('/').pop());

      for (const location of locations) {
        try {
          const ringRes = await kms.projects.locations.keyRings.list({
            parent: `projects/${project}/locations/${location}`,
          });
          const rings = ringRes.data.keyRings ?? [];

          for (const ring of rings) {
            const ringName = ring.name?.split('/').pop() ?? 'unknown';

            try {
              const keyRes = await kms.projects.locations.keyRings.cryptoKeys.list({
                parent: ring.name!,
                versionView: 'FULL',
              });
              const keys = keyRes.data.cryptoKeys ?? [];

              for (const key of keys) {
                const keyName    = key.name?.split('/').pop() ?? 'unknown';
                const keyPurpose = key.purpose ?? 'UNKNOWN';
                const fullName   = `${location}/${ringName}/${keyName}`;

                // 1. Key rotation not configured
                if (!key.rotationPeriod && keyPurpose === 'ENCRYPT_DECRYPT') {
                  findings.push(this.finding(
                    'Cloud KMS key has no automatic rotation configured',
                    `KMS key "${fullName}" in project "${project}" has no rotation schedule. Without automatic rotation, the same key material is used indefinitely, increasing the impact of a key compromise.`,
                    'HIGH',
                    { key: fullName, project, location, ring: ringName, purpose: keyPurpose },
                    'Configure automatic key rotation with a period of 90 days or less. Set the rotationPeriod and nextRotationTime on the crypto key.',
                    ['kms', 'key-rotation'],
                  ));
                }

                // 2. Rotation period too long
                if (key.rotationPeriod) {
                  const rotationDays = parseInt(key.rotationPeriod.replace('s', ''), 10) / 86400;
                  if (rotationDays > MAX_ROTATION_DAYS) {
                    findings.push(this.finding(
                      'Cloud KMS key rotation period exceeds 90 days',
                      `KMS key "${fullName}" rotates every ${Math.round(rotationDays)} days. Long rotation periods increase the window of exposure if key material is compromised.`,
                      'MEDIUM',
                      { key: fullName, project, location, ring: ringName, rotationDays: Math.round(rotationDays) },
                      'Reduce the key rotation period to 90 days or less for symmetric encryption keys.',
                      ['kms', 'key-rotation'],
                    ));
                  }
                }

                // 3. Key versions in DESTROY_SCHEDULED state
                try {
                  const verRes = await kms.projects.locations.keyRings.cryptoKeys.cryptoKeyVersions.list({
                    parent: key.name!,
                    filter: 'state=DESTROY_SCHEDULED',
                  });
                  const scheduledForDestruction = verRes.data.cryptoKeyVersions ?? [];
                  if (scheduledForDestruction.length > 0) {
                    findings.push(this.finding(
                      'Cloud KMS key has versions scheduled for destruction',
                      `KMS key "${fullName}" has ${scheduledForDestruction.length} version(s) scheduled for destruction. If these versions are still used by resources, destroying them will result in data loss.`,
                      'HIGH',
                      { key: fullName, project, location, scheduledVersions: scheduledForDestruction.length },
                      'Verify that no data is encrypted with the versions scheduled for destruction before they are destroyed. Check that all resources have been re-encrypted with the current key version.',
                      ['kms', 'key-lifecycle'],
                    ));
                  }
                } catch { /* version list optional */ }

                // 4. Key is publicly accessible via IAM
                try {
                  const iamRes = await kms.projects.locations.keyRings.cryptoKeys.getIamPolicy({
                    resource: key.name!,
                  });
                  const bindings = iamRes.data.bindings ?? [];
                  const publicBinding = bindings.find(b =>
                    (b.members ?? []).some(m => m === 'allUsers' || m === 'allAuthenticatedUsers'),
                  );
                  if (publicBinding) {
                    findings.push(this.finding(
                      'Cloud KMS key is accessible to allUsers or allAuthenticatedUsers',
                      `KMS key "${fullName}" has a public IAM binding with role "${publicBinding.role}". Any internet user can use this key for cryptographic operations.`,
                      'CRITICAL',
                      { key: fullName, project, location, publicRole: publicBinding.role },
                      'Remove allUsers and allAuthenticatedUsers from the KMS key IAM policy immediately.',
                      ['kms', 'public-access'],
                    ));
                  }
                } catch { /* IAM check optional */ }
              }
            } catch { /* key list optional */ }
          }
        } catch { /* location optional */ }
      }
    } catch (err) {
      findings.push(this.finding(
        'GCP KMS scan error',
        `Could not complete Cloud KMS scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service account has roles/cloudkms.viewer on the project.',
      ));
    }

    return findings;
  }
}
