import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class GcpArtifactRegistryScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-ArtifactRegistry');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      const ar = this.client.artifactregistry();

      // List all repositories across all locations
      const repoRes = await ar.projects.locations.repositories.list({
        parent: `projects/${project}/locations/-`,
        pageSize: 500,
      });
      const repositories = repoRes.data.repositories ?? [];

      if (repositories.length === 0) return findings;

      for (const repo of repositories) {
        const repoName = repo.name?.split('/').pop() ?? 'unknown';
        const location = repo.name?.split('/')[3] ?? 'unknown';
        const format   = repo.format ?? 'unknown';

        // 1. Public IAM access on repository
        try {
          const iamRes = await ar.projects.locations.repositories.getIamPolicy({
            resource: repo.name!,
          });
          const bindings = iamRes.data.bindings ?? [];
          const publicBinding = bindings.find(b =>
            (b.members ?? []).some(m => m === 'allUsers' || m === 'allAuthenticatedUsers'),
          );
          if (publicBinding) {
            findings.push(this.finding(
              'Artifact Registry repository is publicly accessible',
              `Artifact Registry repository "${repoName}" (${location}, format: ${format}) has a public IAM binding with role "${publicBinding.role}". Any internet user can pull artifacts, including potentially proprietary or sensitive container images.`,
              'HIGH',
              { repository: repoName, location, project, format, publicRole: publicBinding.role },
              'Remove allUsers and allAuthenticatedUsers from the repository IAM policy. Use service account credentials for CI/CD pipelines.',
              ['artifactregistry', 'public-access'],
            ));
          }
        } catch { /* IAM check optional */ }

        // 2. No CMEK on repository
        if (!repo.kmsKeyName) {
          findings.push(this.finding(
            'Artifact Registry repository does not use a customer-managed encryption key',
            `Artifact Registry repository "${repoName}" (${location}) uses Google-managed encryption. CMEK provides control over encryption key lifecycle and allows revoking access to stored artifacts.`,
            'MEDIUM',
            { repository: repoName, location, project, format },
            'Configure a Cloud KMS key for the repository using the kmsKeyName field. Grant the Artifact Registry service account Cloud KMS CryptoKey Encrypter/Decrypter permissions.',
            ['artifactregistry', 'encryption', 'cmek'],
          ));
        }

        // 3. Vulnerability scanning not enabled (for Docker/OCI repositories)
        if (format === 'DOCKER' || format === 'OCI') {
          const cleanupPolicies = repo.cleanupPolicies ?? {};
          if (Object.keys(cleanupPolicies).length === 0) {
            findings.push(this.finding(
              'Artifact Registry Docker repository has no cleanup policies configured',
              `Docker repository "${repoName}" (${location}) has no cleanup policies. Old, potentially vulnerable image versions accumulate indefinitely, increasing storage costs and the risk of deploying outdated images.`,
              'LOW',
              { repository: repoName, location, project },
              'Configure cleanup policies to automatically delete old image versions. Use tag-based or age-based policies to retain only recent, tagged versions.',
              ['artifactregistry', 'lifecycle', 'container-security'],
            ));
          }
        }

        // 4. No labels / untagged repository (governance)
        if (!repo.labels || Object.keys(repo.labels).length === 0) {
          findings.push(this.finding(
            'Artifact Registry repository has no resource labels',
            `Artifact Registry repository "${repoName}" (${location}) has no labels. Labels are required for cost allocation, compliance classification, and resource ownership tracking.`,
            'LOW',
            { repository: repoName, location, project },
            'Add labels to the repository for team ownership, environment (prod/dev), and data classification. This enables cost reporting and policy enforcement.',
            ['artifactregistry', 'governance', 'labeling'],
          ));
        }

        // 5. Remote repository pointing to unauthenticated upstream
        if (repo.mode === 'REMOTE_REPOSITORY') {
          const upstreamUri = (repo as any).remoteRepositoryConfig?.dockerRepository?.publicRepository ??
            (repo as any).remoteRepositoryConfig?.customRepository?.uri;
          if (upstreamUri && upstreamUri.startsWith('http://')) {
            findings.push(this.finding(
              'Artifact Registry remote repository uses an unencrypted upstream source',
              `Remote repository "${repoName}" (${location}) proxies from an HTTP upstream "${upstreamUri}". Artifacts may be tampered with in transit.`,
              'HIGH',
              { repository: repoName, location, project, upstreamUri },
              'Update the upstream URI to use HTTPS. Verify the upstream registry has valid TLS certificates.',
              ['artifactregistry', 'tls', 'supply-chain'],
            ));
          }
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'GCP Artifact Registry scan error',
        `Could not complete Artifact Registry scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service account has roles/artifactregistry.reader on the project.',
      ));
    }

    return findings;
  }
}
