import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureAKSScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-AKS');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const aksClient = this.client.containerService();

    try {
      const clusters: any[] = [];
      for await (const c of aksClient.managedClusters.list()) clusters.push(c);

      for (const cluster of clusters) {
        const name    = cluster.name ?? 'unknown';
        const rg      = cluster.id?.split('/')[4] ?? 'unknown';
        const addons  = cluster.addonProfiles ?? {};
        const apiProfile = cluster.apiServerAccessProfile;

        // ── RBAC ─────────────────────────────────────────────────────────────
        if (!cluster.enableRbac) {
          findings.push(this.finding(
            'AKS cluster has Kubernetes RBAC disabled',
            `AKS cluster "${name}" does not have Kubernetes RBAC enabled. All authenticated users have the same level of access.`,
            'CRITICAL',
            { cluster: name, resourceGroup: rg },
            'Enable Kubernetes RBAC when creating the cluster. If already deployed, create a new cluster with RBAC enabled and migrate workloads.',
            ['aks', 'rbac'],
          ));
        }

        // ── Azure AD integration ─────────────────────────────────────────────
        const aadProfile = cluster.aadProfile;
        if (!aadProfile?.managed && !aadProfile?.tenantID) {
          findings.push(this.finding(
            'AKS cluster not integrated with Azure Active Directory',
            `AKS cluster "${name}" is not integrated with Azure AD. Kubernetes authentication relies on local service accounts instead of corporate identities.`,
            'HIGH',
            { cluster: name, resourceGroup: rg },
            'Enable Azure AD integration for the AKS cluster to use corporate identities with MFA for cluster access.',
            ['aks', 'authentication', 'aad'],
          ));
        }

        // ── Azure AD: Local accounts should be disabled ──────────────────────
        if (!cluster.disableLocalAccounts) {
          findings.push(this.finding(
            'AKS cluster allows local Kubernetes accounts',
            `AKS cluster "${name}" has local accounts enabled. Local accounts bypass Azure AD authentication, allowing credential-based access that circumvents MFA and Conditional Access policies.`,
            'HIGH',
            { cluster: name, resourceGroup: rg },
            'Set disableLocalAccounts=true. Require all cluster access to go through Azure AD authentication. Use kubelogin for kubectl integration.',
            ['aks', 'authentication', 'local-accounts'],
          ));
        }

        // ── Network policy ──────────────────────────────────────────────────
        const networkPolicy = cluster.networkProfile?.networkPolicy;
        if (!networkPolicy || networkPolicy === 'none') {
          findings.push(this.finding(
            'AKS cluster has no Kubernetes network policy configured',
            `AKS cluster "${name}" does not have a network policy engine (Calico or Azure CNI). All pods can communicate with each other without restriction, enabling lateral movement after a pod compromise.`,
            'HIGH',
            { cluster: name, resourceGroup: rg },
            'Enable network policy (Azure or Calico) at cluster creation and define NetworkPolicy resources to enforce least-privilege pod-to-pod communication.',
            ['aks', 'network-policy'],
          ));
        }

        // ── Private cluster / API server exposure ────────────────────────────
        if (!apiProfile?.enablePrivateCluster) {
          findings.push(this.finding(
            'AKS cluster API server is publicly accessible',
            `AKS cluster "${name}" API server is exposed to the internet. Misconfigured RBAC or stolen credentials can lead to full cluster compromise.`,
            'HIGH',
            { cluster: name, resourceGroup: rg },
            'Enable private cluster to expose the API server only within the virtual network. Use authorized IP ranges as an interim control.',
            ['aks', 'network', 'api-server'],
          ));

          // No authorized IP ranges on public cluster
          const authorizedRanges = apiProfile?.authorizedIPRanges ?? [];
          if (authorizedRanges.length === 0) {
            findings.push(this.finding(
              'AKS cluster API server has no authorized IP ranges configured',
              `AKS cluster "${name}" API server is public with no IP allowlist. Any internet host can attempt to authenticate against the Kubernetes API.`,
              'HIGH',
              { cluster: name, resourceGroup: rg },
              'Configure authorized IP ranges to restrict API server access to known corporate IP ranges until a private cluster migration is completed.',
              ['aks', 'network', 'api-server'],
            ));
          }
        }

        // ── Azure Policy add-on (OPA/Gatekeeper) ────────────────────────────
        const azurePolicyAddon = addons['azurepolicy'];
        if (!azurePolicyAddon?.enabled) {
          findings.push(this.finding(
            'AKS cluster Azure Policy add-on is not enabled',
            `AKS cluster "${name}" does not have the Azure Policy add-on (OPA Gatekeeper) enabled. Without policy enforcement, privileged containers, host network access, and insecure pod configurations can run unconstrained.`,
            'HIGH',
            { cluster: name, resourceGroup: rg },
            'Enable the Azure Policy add-on for AKS. Assign the "Kubernetes cluster pod security baseline standards" initiative to prevent privileged containers, hostPID, hostNetwork, and dangerous capabilities.',
            ['aks', 'policy', 'privileged-containers'],
          ));
        }

        // ── OIDC Issuer / Workload Identity ──────────────────────────────────
        const oidcEnabled      = cluster.oidcIssuerProfile?.enabled ?? false;
        const workloadIdentity = cluster.securityProfile?.workloadIdentity?.enabled ?? false;

        if (!oidcEnabled || !workloadIdentity) {
          findings.push(this.finding(
            'AKS cluster workload identity (OIDC) is not enabled',
            `AKS cluster "${name}" does not have OIDC Issuer${!oidcEnabled ? '' : ''} and/or Workload Identity enabled. Without workload identity, pods must use shared service principal credentials or node-level managed identity, which grants all pods equal access.`,
            'MEDIUM',
            { cluster: name, oidcEnabled, workloadIdentityEnabled: workloadIdentity, resourceGroup: rg },
            'Enable OIDC Issuer and Workload Identity on the cluster. Use federated credentials to assign per-workload Azure AD identities, giving each pod the minimum Azure RBAC permissions it needs.',
            ['aks', 'identity', 'workload-identity'],
          ));
        }

        // ── Image Cleaner ────────────────────────────────────────────────────
        const imageCleanerEnabled = cluster.securityProfile?.imageCleaner?.enabled ?? false;
        if (!imageCleanerEnabled) {
          findings.push(this.finding(
            'AKS cluster image cleaner is not enabled',
            `AKS cluster "${name}" does not have the Image Cleaner feature enabled. Stale and potentially vulnerable container images accumulate on nodes, increasing the attack surface if those images contain known CVEs.`,
            'LOW',
            { cluster: name, resourceGroup: rg },
            'Enable Image Cleaner in the cluster security profile to automatically remove unused and stale images from cluster nodes.',
            ['aks', 'image-hygiene'],
          ));
        }

        // ── HTTP application routing add-on ──────────────────────────────────
        const httpRoutingAddon = addons['httpApplicationRouting'];
        if (httpRoutingAddon?.enabled) {
          findings.push(this.finding(
            'AKS cluster has HTTP application routing add-on enabled',
            `AKS cluster "${name}" has the HTTP application routing add-on enabled. This add-on is intended for development/testing and creates a publicly accessible DNS zone and ingress controller with no authentication or rate limiting.`,
            'HIGH',
            { cluster: name, resourceGroup: rg },
            'Disable the HTTP application routing add-on in production. Use a production-grade ingress controller (NGINX, AGIC) with TLS, authentication, and WAF integration.',
            ['aks', 'ingress', 'development-feature'],
          ));
        }

        // ── Container Insights (monitoring) ──────────────────────────────────
        const omsAddon = addons['omsagent'];
        if (!omsAddon?.enabled) {
          findings.push(this.finding(
            'AKS cluster Container Insights monitoring is not enabled',
            `AKS cluster "${name}" does not have Container Insights (OMS agent) enabled. Without monitoring, runtime anomalies, resource exhaustion, and pod crashes cannot be detected or alerted on.`,
            'MEDIUM',
            { cluster: name, resourceGroup: rg },
            'Enable Container Insights via the Azure Monitor add-on. Configure alerts for CPU/memory thresholds, pod restart storms, and node health.',
            ['aks', 'monitoring'],
          ));
        }

        // ── Automatic upgrade channel ────────────────────────────────────────
        const upgradeChannel = cluster.autoUpgradeProfile?.upgradeChannel ?? 'none';
        if (upgradeChannel === 'none') {
          findings.push(this.finding(
            'AKS cluster automatic upgrade is disabled',
            `AKS cluster "${name}" has no automatic upgrade channel configured. The cluster may fall behind on Kubernetes security patches and supported versions.`,
            'MEDIUM',
            { cluster: name, upgradeChannel, resourceGroup: rg },
            'Enable the "patch" upgrade channel to automatically apply patch-level security updates to the Kubernetes control plane. Test in non-production first.',
            ['aks', 'patching'],
          ));
        }

        // ── Node OS upgrade channel ──────────────────────────────────────────
        const nodeUpgrade = (cluster as any).nodeOSUpgradeChannel ?? 'None';
        if (nodeUpgrade === 'None') {
          findings.push(this.finding(
            'AKS node OS automatic upgrade is disabled',
            `AKS cluster "${name}" node OS automatic security patching is not configured. Node VMs may have unpatched OS vulnerabilities.`,
            'MEDIUM',
            { cluster: name, nodeOsUpgradeChannel: nodeUpgrade, resourceGroup: rg },
            'Set nodeOSUpgradeChannel to "SecurityPatch" or "NodeImage" to keep node OS packages patched automatically.',
            ['aks', 'patching', 'node-os'],
          ));
        }

        // ── Disk encryption ──────────────────────────────────────────────────
        if (!cluster.diskEncryptionSetID) {
          findings.push(this.finding(
            'AKS cluster node disks not encrypted with customer-managed key',
            `AKS cluster "${name}" does not use a disk encryption set. Node OS and data disks use platform-managed keys only.`,
            'MEDIUM',
            { cluster: name, resourceGroup: rg },
            'Associate a disk encryption set backed by a customer-managed key in Key Vault when creating the cluster.',
            ['aks', 'encryption'],
          ));
        }

        // ── Kubernetes version end-of-life check ─────────────────────────────
        const k8sVersion = cluster.currentKubernetesVersion ?? cluster.kubernetesVersion ?? '';
        if (k8sVersion) {
          const [major, minor] = k8sVersion.split('.').map(Number);
          // AKS supports N-2 minor versions; warn if minor is ≤ 26 (as of 2026)
          if (!isNaN(major) && !isNaN(minor) && major === 1 && minor <= 26) {
            findings.push(this.finding(
              'AKS cluster is running an end-of-life Kubernetes version',
              `AKS cluster "${name}" runs Kubernetes ${k8sVersion}, which has reached or is approaching end-of-support. EOL versions no longer receive CVE patches.`,
              'HIGH',
              { cluster: name, kubernetesVersion: k8sVersion, resourceGroup: rg },
              'Upgrade the cluster to a supported Kubernetes version. Enable an automatic upgrade channel to prevent future EOL drift.',
              ['aks', 'patching', 'eol-version'],
            ));
          }
        }

        // ── Node pool checks ─────────────────────────────────────────────────
        const nodePools = cluster.agentPoolProfiles ?? [];
        for (const pool of nodePools) {
          const poolName = pool.name ?? 'unknown';

          // Node image version — auto-upgrade disabled at pool level
          if (pool.nodeImageVersion && !pool.upgradeSettings?.maxSurge) {
            // This is informational — just check if surge upgrade is configured
          }

          // OS disk size — very small may indicate ephemeral disk misconfiguration
          const osDiskSizeGB = pool.osDiskSizeGB ?? 0;
          if (osDiskSizeGB > 0 && osDiskSizeGB < 30) {
            findings.push(this.finding(
              'AKS node pool OS disk size is unusually small',
              `Node pool "${poolName}" in cluster "${name}" has an OS disk size of ${osDiskSizeGB} GB. Small OS disks can cause node instability under load and complicate OS patching.`,
              'LOW',
              { cluster: name, nodePool: poolName, osDiskSizeGB, resourceGroup: rg },
              'Increase the node pool OS disk size to at least 128 GB for production workloads. Consider using ephemeral OS disks for better performance.',
              ['aks', 'node-pool', 'configuration'],
            ));
          }
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure AKS scan error',
        `Could not complete AKS scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Azure Kubernetes Service Contributor or Reader permissions.',
      ));
    }

    return findings;
  }
}
