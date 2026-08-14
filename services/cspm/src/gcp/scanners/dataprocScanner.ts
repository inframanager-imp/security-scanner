// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

interface Cluster {
  clusterName?: string | null;
  clusterUuid?: string | null;
  config?: {
    encryptionConfig?: {
      gcePdKmsKeyName?: string | null;
    } | null;
  } | null;
}

export class GcpDataprocScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-Dataproc');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      const regions = await this.listRegions(project);

      for (const region of regions) {
        try {
          const clusters = await this.listClusters(project, region);
          for (const cluster of clusters) {
            const clusterName = cluster.clusterName ?? cluster.clusterUuid ?? 'unnamed-cluster';

            // dataproc_encrypted_with_cmks_disabled
            if (!cluster.config?.encryptionConfig?.gcePdKmsKeyName) {
              findings.push(this.emit(
                'dataproc_encrypted_with_cmks_disabled',
                { project, region, cluster: clusterName },
                { message: `Dataproc cluster "${clusterName}" in project "${project}" (region ${region}) is not encrypted with a customer-managed encryption key — persistent disks rely on Google-managed keys only.` },
              ));
            }
          }
        } catch { /* region without Dataproc access/quota — skip */ }
      }
    } catch (err) {
      findings.push(this.emit(
        'dataproc_encrypted_with_cmks_disabled',
        { error: (err as Error).message },
        { severity: 'INFO', message: `GCP Dataproc scan error: ${(err as Error).message}`, remediation: 'Ensure the service account has the roles/dataproc.viewer and roles/compute.viewer permissions.' },
      ));
    }

    return findings;
  }

  private async listRegions(project: string): Promise<string[]> {
    const compute = this.client.compute();
    const regions: string[] = [];
    let pageToken: string | undefined;
    do {
      const res = await compute.regions.list({ project, pageToken });
      for (const r of res.data.items ?? []) {
        if (r.name) regions.push(r.name);
      }
      pageToken = res.data.nextPageToken ?? undefined;
    } while (pageToken);
    return regions;
  }

  private async listClusters(project: string, region: string): Promise<Cluster[]> {
    const dataproc = this.client.dataproc();
    const clusters: Cluster[] = [];
    let pageToken: string | undefined;
    do {
      const res = await dataproc.projects.regions.clusters.list({ projectId: project, region, pageToken });
      clusters.push(...(res.data.clusters ?? []));
      pageToken = res.data.nextPageToken ?? undefined;
    } while (pageToken);
    return clusters;
  }
}

export default GcpDataprocScanner;
