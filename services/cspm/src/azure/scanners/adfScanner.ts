import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureDataFactoryScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-DataFactory');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const adfClient = this.client.dataFactory();

      const factories: any[] = [];
      for await (const f of adfClient.factories.list()) factories.push(f);

      if (factories.length === 0) return findings;

      for (const factory of factories) {
        const name = factory.name ?? 'unknown';
        const rg   = factory.id?.split('/')[4] ?? 'unknown';

        // 1. Public network access enabled
        const publicAccess = factory.publicNetworkAccess ?? 'Enabled';
        if (publicAccess === 'Enabled') {
          findings.push(this.finding(
            'Azure Data Factory has public network access enabled',
            `Data Factory "${name}" is accessible from the public internet. The ADF authoring UI and REST API are exposed, increasing risk of credential theft and unauthorized pipeline execution.`,
            'HIGH',
            { factory: name, resourceGroup: rg },
            'Set publicNetworkAccess to "Disabled" and configure private endpoints for the Data Factory to restrict access to internal VNet consumers.',
            ['datafactory', 'network', 'public-access'],
          ));
        }

        // 2. No managed VNet (all integration runtimes run on public Azure)
        const managedVNet = factory.managedVirtualNetwork;
        if (!managedVNet) {
          findings.push(this.finding(
            'Azure Data Factory has no managed virtual network configured',
            `Data Factory "${name}" has no Managed VNet. Managed Integration Runtimes run on shared public Azure infrastructure and cannot connect to private data sources without self-hosted IRs or public endpoints on data stores.`,
            'HIGH',
            { factory: name, resourceGroup: rg },
            'Enable the Managed Virtual Network on the Data Factory. Use Managed Private Endpoints to connect to data sources without exposing them publicly.',
            ['datafactory', 'network', 'managed-vnet'],
          ));
        }

        // 3. Managed identity not assigned
        const hasManagedIdentity = factory.identity?.type &&
          (factory.identity.type.includes('SystemAssigned') || factory.identity.type.includes('UserAssigned'));
        if (!hasManagedIdentity) {
          findings.push(this.finding(
            'Azure Data Factory has no managed identity assigned',
            `Data Factory "${name}" has no managed identity. Without managed identity, linked services (Key Vault, Storage, SQL, ADLS) must use connection strings or stored credentials.`,
            'MEDIUM',
            { factory: name, resourceGroup: rg },
            'Enable system-assigned managed identity on the Data Factory. Update all linked services to authenticate using Managed Identity instead of connection strings or service principal credentials.',
            ['datafactory', 'identity'],
          ));
        }

        // 4. Customer-managed key (CMK)
        const encryptionKeyIdentifier = factory.encryption?.keyName;
        if (!encryptionKeyIdentifier) {
          findings.push(this.finding(
            'Azure Data Factory does not use a customer-managed encryption key',
            `Data Factory "${name}" uses Microsoft-managed keys for encrypting pipeline metadata, linked service credentials, and integration runtime configurations. CMK provides key lifecycle control and revocation capability.`,
            'MEDIUM',
            { factory: name, resourceGroup: rg },
            'Configure a customer-managed key from Azure Key Vault for the Data Factory encryption settings.',
            ['datafactory', 'encryption', 'cmk'],
          ));
        }

        // 5. Diagnostic logs not configured
        try {
          const monitorClient = this.client.monitor();
          const settingsResult = await monitorClient.diagnosticSettings.list(factory.id!);
          const settings: any[] = settingsResult.value ?? [];
          const hasLogs = settings.some(s =>
            s.logs?.some((l: any) => l.enabled) || s.metrics?.some((m: any) => m.enabled),
          );
          if (!hasLogs) {
            findings.push(this.finding(
              'Azure Data Factory has no diagnostic logs configured',
              `Data Factory "${name}" has no diagnostic settings. Without logs, pipeline runs, data movement operations, and authentication events cannot be audited.`,
              'MEDIUM',
              { factory: name, resourceGroup: rg },
              'Enable diagnostic settings to capture PipelineRuns, TriggerRuns, ActivityRuns, and SSISIntegrationRuntimeLogs categories to a Log Analytics workspace.',
              ['datafactory', 'logging'],
            ));
          }
        } catch { /* optional */ }

        // 6. Git configuration absent — no source control
        const gitHub = (factory as any).repoConfiguration;
        if (!gitHub) {
          findings.push(this.finding(
            'Azure Data Factory has no source control (Git) configured',
            `Data Factory "${name}" has no Git repository configured. Pipeline definitions, linked services, and datasets are not version controlled, making it impossible to audit changes, roll back modifications, or detect unauthorized pipeline edits.`,
            'LOW',
            { factory: name, resourceGroup: rg },
            'Connect the Data Factory to Azure DevOps Repos or GitHub for version control of all pipeline assets. Require PR reviews before publishing changes to the live factory.',
            ['datafactory', 'change-management'],
          ));
        }

        // 7. Self-Hosted IR — check if any IR has expired node
        try {
          const irs: any[] = [];
          for await (const ir of adfClient.integrationRuntimes.listByFactory(rg, name)) irs.push(ir);

          for (const ir of irs) {
            if (ir.properties?.typeProperties?.type === 'SelfHosted') {
              const nodes = ir.properties?.typeProperties?.nodes ?? [];
              const expiredNodes = nodes.filter((n: any) => n.status === 'NeedRegistration' || n.status === 'Offline');
              if (expiredNodes.length > 0) {
                findings.push(this.finding(
                  'Azure Data Factory Self-Hosted Integration Runtime has offline/expired nodes',
                  `Data Factory "${name}" Self-Hosted IR "${ir.name}" has ${expiredNodes.length} offline or unregistered node(s). Offline SHIR nodes may run outdated software versions with unpatched vulnerabilities.`,
                  'MEDIUM',
                  { factory: name, ir: ir.name, resourceGroup: rg, offlineNodes: expiredNodes.length },
                  'Investigate and re-register or decommission offline SHIR nodes. Keep SHIR software updated to the latest version.',
                  ['datafactory', 'shir', 'patching'],
                ));
              }
            }
          }
        } catch { /* optional */ }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Data Factory scan error',
        `Could not complete Data Factory scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Data Factory resources.',
      ));
    }

    return findings;
  }
}
