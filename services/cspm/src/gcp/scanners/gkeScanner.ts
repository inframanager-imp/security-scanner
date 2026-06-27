import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const EOL_K8S_VERSIONS = ['1.24', '1.25', '1.26', '1.27'];

export class GcpGKEScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-GKE');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      const container = this.client.container();
      const res       = await container.projects.locations.clusters.list({
        parent: `projects/${project}/locations/-`,
      });
      const clusters = res.data.clusters ?? [];

      if (clusters.length === 0) return findings;

      for (const cluster of clusters) {
        const name     = cluster.name ?? 'unknown';
        const location = cluster.location ?? 'unknown';
        const version  = cluster.currentMasterVersion ?? 'unknown';

        // 1. Public master endpoint
        const masterEndpoint = cluster.endpoint;
        const masterAuth     = cluster.masterAuthorizedNetworksConfig;
        if (masterEndpoint && (!masterAuth?.enabled || (masterAuth?.cidrBlocks ?? []).length === 0)) {
          findings.push(this.finding(
            'GKE cluster API server is publicly accessible without authorized network restrictions',
            `GKE cluster "${name}" (${location}) has a public endpoint "${masterEndpoint}" with no authorized master networks configured. Any internet host can reach the Kubernetes API server.`,
            'CRITICAL',
            { cluster: name, location, project, endpoint: masterEndpoint },
            'Enable master authorized networks and restrict access to specific IP ranges (e.g., your corporate NAT IPs, bastion host). Consider using Private Cluster mode to eliminate the public endpoint entirely.',
            ['gke', 'network', 'api-server'],
          ));
        }

        // 2. Private cluster not enabled
        if (!cluster.privateClusterConfig?.enablePrivateNodes) {
          findings.push(this.finding(
            'GKE cluster nodes have public IP addresses',
            `GKE cluster "${name}" (${location}) does not use private nodes. All worker nodes have public IP addresses, exposing the node OS and kubelet to internet-based attacks.`,
            'HIGH',
            { cluster: name, location, project },
            'Enable private nodes in the cluster configuration. Node VMs will only have private IP addresses and communicate via Cloud NAT for egress.',
            ['gke', 'network', 'private-nodes'],
          ));
        }

        // 3. Legacy authentication (username/password or client certificate)
        const legacyAuth = cluster.masterAuth;
        if (legacyAuth?.username || legacyAuth?.clientCertificateConfig?.issueClientCertificate) {
          findings.push(this.finding(
            'GKE cluster has legacy authentication enabled',
            `GKE cluster "${name}" (${location}) has static username/password or client certificate authentication enabled. These legacy methods cannot use MFA and are harder to rotate than IAM-based credentials.`,
            'CRITICAL',
            { cluster: name, location, project, hasUsername: !!legacyAuth?.username },
            'Disable static username/password and client certificate authentication. Use Workload Identity and RBAC with IAM for authentication. Update all kubeconfig files to use gcloud credential helpers.',
            ['gke', 'authentication'],
          ));
        }

        // 4. RBAC disabled
        if (!cluster.legacyAbac?.enabled === false) {
          // legacyAbac.enabled = true means ABAC (not RBAC) is active
          if (cluster.legacyAbac?.enabled) {
            findings.push(this.finding(
              'GKE cluster has legacy ABAC authorization enabled',
              `GKE cluster "${name}" (${location}) has legacy Attribute-Based Access Control (ABAC) enabled. ABAC is deprecated and overly permissive — it grants users full cluster access.`,
              'CRITICAL',
              { cluster: name, location, project },
              'Disable legacy ABAC (legacyAbac=false). Configure Kubernetes RBAC with least-privilege Role and ClusterRole bindings for all users and service accounts.',
              ['gke', 'rbac', 'authorization'],
            ));
          }
        }

        // 5. Network policy not enabled
        if (!cluster.networkPolicy?.enabled) {
          findings.push(this.finding(
            'GKE cluster has no Kubernetes network policy configured',
            `GKE cluster "${name}" (${location}) has no network policy (Calico/Dataplane V2). All pods can communicate with each other across namespaces by default, violating micro-segmentation principles.`,
            'HIGH',
            { cluster: name, location, project },
            'Enable network policy on the cluster and deploy Kubernetes NetworkPolicy resources to restrict pod-to-pod communication to only the required traffic flows.',
            ['gke', 'network-policy'],
          ));
        }

        // 6. Workload Identity not enabled
        if (!cluster.workloadIdentityConfig?.workloadPool) {
          findings.push(this.finding(
            'GKE cluster does not have Workload Identity enabled',
            `GKE cluster "${name}" (${location}) does not use Workload Identity. Without Workload Identity, pods must use node-level service account credentials or mounted service account key files to access GCP APIs.`,
            'HIGH',
            { cluster: name, location, project },
            'Enable Workload Identity on the cluster. Map Kubernetes service accounts to GCP service accounts using IAM bindings. Remove any service account key files from pod configurations.',
            ['gke', 'workload-identity'],
          ));
        }

        // 7. Binary Authorization not enabled
        if (!cluster.binaryAuthorization?.evaluationMode || cluster.binaryAuthorization?.evaluationMode === 'DISABLED') {
          findings.push(this.finding(
            'GKE cluster does not enforce Binary Authorization',
            `GKE cluster "${name}" (${location}) has Binary Authorization disabled. Any container image can be deployed to the cluster, including unvetted or malicious images.`,
            'MEDIUM',
            { cluster: name, location, project },
            'Enable Binary Authorization on the cluster and create attestation policies that require images to be signed by trusted authorities (e.g., Cloud Build, Vulnerability Scanning) before deployment.',
            ['gke', 'binary-authorization', 'supply-chain'],
          ));
        }

        // 8. Shielded nodes not enabled
        if (!cluster.shieldedNodes?.enabled) {
          findings.push(this.finding(
            'GKE cluster does not use Shielded Nodes',
            `GKE cluster "${name}" (${location}) has Shielded Nodes disabled. Shielded Nodes prevent node-level rootkit attacks and cryptographically verify node integrity.`,
            'MEDIUM',
            { cluster: name, location, project },
            'Enable Shielded Nodes on the GKE cluster. This provides secure boot and vTPM for all node pool VMs.',
            ['gke', 'shielded-nodes'],
          ));
        }

        // 9. Control plane logging not enabled
        const loggingConfig = cluster.loggingConfig;
        const systemComp    = loggingConfig?.componentConfig?.enableComponents ?? [];
        const hasAPIServer  = systemComp.includes('SYSTEM_COMPONENTS') || systemComp.includes('APISERVER');
        if (!hasAPIServer && cluster.loggingService !== 'logging.googleapis.com/kubernetes') {
          findings.push(this.finding(
            'GKE cluster control plane audit logging is not enabled',
            `GKE cluster "${name}" (${location}) does not send Kubernetes API server audit logs to Cloud Logging. Control plane actions (kubectl commands, RBAC changes) cannot be audited.`,
            'HIGH',
            { cluster: name, location, project, loggingService: cluster.loggingService },
            'Set loggingService to "logging.googleapis.com/kubernetes" and enable SYSTEM_COMPONENTS and APISERVER in the logging component config.',
            ['gke', 'logging', 'audit'],
          ));
        }

        // 10. EOL Kubernetes version
        const majorMinor = version.split('.').slice(0, 2).join('.');
        if (EOL_K8S_VERSIONS.some(v => majorMinor.startsWith(v))) {
          findings.push(this.finding(
            'GKE cluster runs an end-of-life Kubernetes version',
            `GKE cluster "${name}" (${location}) runs Kubernetes ${version} which is end-of-life and no longer receives security patches. Unpatched vulnerabilities in the control plane or node components can be exploited.`,
            'HIGH',
            { cluster: name, location, project, version },
            'Upgrade the GKE cluster to a supported Kubernetes version. Enable GKE auto-upgrade to automatically keep clusters on supported versions.',
            ['gke', 'eol-version'],
          ));
        }

        // 11. Auto-upgrade disabled on node pools
        const nodePools = cluster.nodePools ?? [];
        for (const pool of nodePools) {
          if (!pool.management?.autoUpgrade) {
            findings.push(this.finding(
              'GKE node pool has auto-upgrade disabled',
              `Node pool "${pool.name}" in GKE cluster "${name}" (${location}) has auto-upgrade disabled. Nodes will not receive security patches for the operating system or node components automatically.`,
              'MEDIUM',
              { cluster: name, nodePool: pool.name, location, project },
              'Enable auto-upgrade on the node pool to automatically apply OS and Kubernetes patch updates.',
              ['gke', 'node-pool', 'auto-upgrade'],
            ));
          }

          // 12. Auto-repair disabled
          if (!pool.management?.autoRepair) {
            findings.push(this.finding(
              'GKE node pool has auto-repair disabled',
              `Node pool "${pool.name}" in GKE cluster "${name}" (${location}) has auto-repair disabled. Unhealthy nodes will not be automatically repaired or replaced, potentially leaving workloads in a degraded state.`,
              'MEDIUM',
              { cluster: name, nodePool: pool.name, location, project },
              'Enable auto-repair on the node pool.',
              ['gke', 'node-pool', 'auto-repair'],
            ));
          }

          // 13. Secure boot on node pool
          if (!pool.config?.shieldedInstanceConfig?.enableSecureBoot) {
            findings.push(this.finding(
              'GKE node pool does not enable Secure Boot',
              `Node pool "${pool.name}" in GKE cluster "${name}" (${location}) has Secure Boot disabled. Secure Boot verifies kernel and driver signatures at boot time, protecting against bootkit attacks.`,
              'LOW',
              { cluster: name, nodePool: pool.name, location, project },
              'Enable Secure Boot on the node pool by setting shieldedInstanceConfig.enableSecureBoot=true.',
              ['gke', 'node-pool', 'secure-boot'],
            ));
          }
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'GCP GKE scan error',
        `Could not complete GKE cluster scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service account has roles/container.viewer on the project.',
      ));
    }

    return findings;
  }
}
