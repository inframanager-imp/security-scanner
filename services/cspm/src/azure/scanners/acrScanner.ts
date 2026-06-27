import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureACRScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-ACR');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const acrClient = this.client.containerRegistry();

      const registries: any[] = [];
      for await (const r of acrClient.registries.list()) registries.push(r);

      if (registries.length === 0) return findings;

      for (const registry of registries) {
        const name = registry.name ?? 'unknown';
        const rg   = registry.id?.split('/')[4] ?? 'unknown';
        const sku  = registry.sku?.name ?? 'Basic';

        // 1. Admin user enabled — static credential that can't be rotated granularly
        if (registry.adminUserEnabled) {
          findings.push(this.finding(
            'ACR admin user account is enabled',
            `Container registry "${name}" has the admin user account enabled. The admin account provides a single shared credential with full push/pull access and cannot be scoped to specific repositories.`,
            'HIGH',
            { registry: name, resourceGroup: rg, sku },
            'Disable the admin user account. Use Azure AD service principals or managed identities with scoped ACR roles (AcrPull, AcrPush) instead.',
            ['acr', 'authentication'],
          ));
        }

        // 2. Public network access
        const publicAccess = registry.publicNetworkAccess ?? 'Enabled';
        if (publicAccess === 'Enabled') {
          const networkRuleSet = registry.networkRuleSet;
          const defaultAction  = networkRuleSet?.defaultAction ?? 'Allow';
          if (defaultAction === 'Allow') {
            findings.push(this.finding(
              'Container registry is publicly accessible from all networks',
              `ACR "${name}" allows unauthenticated network access from any IP. Even with authentication, public exposure enlarges the attack surface for credential brute-force and token theft.`,
              'HIGH',
              { registry: name, resourceGroup: rg, sku },
              'Set publicNetworkAccess to Disabled and use Private Endpoint for registry access from VNets. If public access is required, restrict via IP network rules.',
              ['acr', 'network', 'public-access'],
            ));
          }
        }

        // 3. Content trust (image signing) — Premium SKU only
        if (sku === 'Premium') {
          const trustPolicy = registry.policies?.trustPolicy;
          if (!trustPolicy || trustPolicy.status !== 'enabled') {
            findings.push(this.finding(
              'ACR content trust (image signing) is not enabled',
              `Container registry "${name}" does not have content trust enabled. Without image signing, there is no cryptographic guarantee that pulled images are authentic and unmodified.`,
              'MEDIUM',
              { registry: name, resourceGroup: rg, sku },
              'Enable content trust on the Premium SKU registry. Sign images using Docker Content Trust (Notary v1) or Notation (Notary v2 / CNCF). Enforce trust policies on AKS clusters using Azure Policy.',
              ['acr', 'image-integrity', 'supply-chain'],
            ));
          }
        }

        // 4. Vulnerability scanning / image assessment
        const retentionPolicy = registry.policies?.retentionPolicy;
        const exportPolicy    = registry.policies?.exportPolicy;

        // Check if quarantine policy is enabled (indicates security-conscious config)
        const quarantinePolicy = (registry.policies as any)?.quarantinePolicy;
        if (!quarantinePolicy || quarantinePolicy.status !== 'enabled') {
          findings.push(this.finding(
            'ACR quarantine policy is not enabled',
            `Container registry "${name}" does not have the quarantine policy enabled. Newly pushed images are immediately pullable before any vulnerability scan can complete, allowing vulnerable images to enter production.`,
            'MEDIUM',
            { registry: name, resourceGroup: rg, sku },
            'Enable the quarantine policy on the registry. Images will be quarantined on push and only made available after a security scan passes. Requires Premium SKU.',
            ['acr', 'image-scanning', 'supply-chain'],
          ));
        }

        // 5. Export policy — should be disabled for high-security registries (Premium)
        if (sku === 'Premium' && exportPolicy?.status !== 'disabled') {
          findings.push(this.finding(
            'ACR export policy allows image export outside the registry',
            `Container registry "${name}" allows image export via ACR import/export. This can be used to exfiltrate proprietary container images.`,
            'LOW',
            { registry: name, resourceGroup: rg },
            'If images are sensitive, disable the export policy to prevent images from being exported to external registries.',
            ['acr', 'data-exfiltration'],
          ));
        }

        // 6. Retention policy for untagged manifests
        if (!retentionPolicy || retentionPolicy.status !== 'enabled') {
          findings.push(this.finding(
            'ACR retention policy for untagged images is not configured',
            `Container registry "${name}" has no retention policy for untagged manifests. Over time, stale and potentially vulnerable image layers accumulate, increasing storage costs and the attack surface.`,
            'LOW',
            { registry: name, resourceGroup: rg, sku },
            'Enable a retention policy to automatically delete untagged manifests after a defined number of days (e.g., 30 days). Requires Premium SKU.',
            ['acr', 'image-hygiene'],
          ));
        }

        // 7. Basic SKU — lacks security features
        if (sku === 'Basic') {
          findings.push(this.finding(
            'Container registry is using the Basic SKU',
            `ACR "${name}" uses the Basic SKU, which lacks Private Endpoint support, content trust, geo-replication, and advanced network rules. Production registries should use Standard or Premium SKU.`,
            'MEDIUM',
            { registry: name, resourceGroup: rg, sku },
            'Upgrade to Standard or Premium SKU to enable Private Endpoint, zone redundancy, and content trust features.',
            ['acr', 'sku', 'configuration'],
          ));
        }

        // 8. Geo-replication (Premium) — for DR
        if (sku === 'Premium') {
          try {
            const replications: any[] = [];
            for await (const r of acrClient.replications.list(rg, name)) replications.push(r);
            if (replications.length === 0) {
              findings.push(this.finding(
                'ACR has no geo-replication configured',
                `Container registry "${name}" (Premium SKU) has no geo-replication. If the primary region experiences an outage, image pulls will fail for workloads in other regions.`,
                'LOW',
                { registry: name, resourceGroup: rg },
                'Configure geo-replication to at least one additional region to ensure registry availability during regional outages.',
                ['acr', 'availability'],
              ));
            }
          } catch { /* replication check optional */ }
        }

        // 9. Per-repository image vulnerability scan results (if available via ARM)
        try {
          const runs: any[] = [];
          for await (const run of acrClient.runs.list(rg, name)) {
            runs.push(run);
            if (runs.length >= 20) break;
          }
          const failedRuns = runs.filter(r => r.status === 'Failed' || r.status === 'Error');
          if (failedRuns.length > 0) {
            findings.push(this.finding(
              'ACR image build/scan runs have failures',
              `Container registry "${name}" has ${failedRuns.length} failed ACR Task run(s). Failed build or scan tasks may indicate broken pipelines or unscanned images entering production.`,
              'MEDIUM',
              {
                registry: name,
                resourceGroup: rg,
                failedRunCount: failedRuns.length,
                recentFailures: failedRuns.slice(0, 5).map(r => ({ id: r.runId, type: r.type, finishTime: r.finishTime })),
              },
              'Investigate failed ACR Task runs. Ensure all images undergo vulnerability scanning via ACR Tasks or an integrated CI/CD pipeline before being tagged as production-ready.',
              ['acr', 'image-scanning', 'pipeline'],
            ));
          }
        } catch { /* ACR Tasks optional */ }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure ACR scan error',
        `Could not complete Container Registry scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Container Registry resources.',
      ));
    }

    return findings;
  }
}
