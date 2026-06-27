import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureSearchScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-AISearch');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const searchClient = this.client.search();

      const services: any[] = [];
      for await (const svc of searchClient.services.listBySubscription()) services.push(svc);

      if (services.length === 0) return findings;

      for (const svc of services) {
        const name = svc.name ?? 'unknown';
        const rg   = svc.id?.split('/')[4] ?? 'unknown';
        const sku  = svc.sku?.name ?? 'basic';

        // 1. Public network access enabled
        const publicAccess = svc.publicNetworkAccess ?? 'enabled';
        if (publicAccess === 'enabled') {
          findings.push(this.finding(
            'Azure AI Search service has public network access enabled',
            `AI Search service "${name}" is accessible from the public internet. Search indexes, which may contain sensitive indexed data, are exposed to unauthorized query attempts.`,
            'HIGH',
            { service: name, resourceGroup: rg, sku },
            'Set publicNetworkAccess to "disabled" and configure Private Endpoints to allow access only from trusted VNets.',
            ['search', 'network', 'public-access'],
          ));
        }

        // 2. Local (API key) authentication — prefer Entra ID
        const localAuthDisabled = svc.disableLocalAuth === true;
        if (!localAuthDisabled) {
          findings.push(this.finding(
            'Azure AI Search service uses API key authentication instead of Microsoft Entra ID',
            `AI Search service "${name}" has local API key authentication enabled. API keys are shared secrets that cannot be scoped per-user, do not support MFA, and must be manually rotated.`,
            'MEDIUM',
            { service: name, resourceGroup: rg },
            'Set disableLocalAuth to true and configure Entra ID RBAC (Search Index Data Reader/Contributor roles) for all clients. Update application connection logic to use Managed Identity or service principal tokens.',
            ['search', 'authentication'],
          ));
        }

        // 3. Minimum TLS version
        // Search services always use TLS 1.2+; however, custom skillsets may use HTTP
        // Flag if a linked skillset endpoint uses HTTP
        try {
          const skillsets: any[] = [];
          for await (const ss of (searchClient as any).skillsets?.listBySearchService?.(rg, name) ?? []) {
            skillsets.push(ss);
          }
          const httpSkillsets = skillsets.filter((ss: any) =>
            ss.skills?.some((skill: any) =>
              skill.uri?.startsWith('http://'),
            ),
          );
          if (httpSkillsets.length > 0) {
            findings.push(this.finding(
              'Azure AI Search skillset uses an HTTP (non-HTTPS) endpoint',
              `AI Search service "${name}" has ${httpSkillsets.length} skillset(s) with HTTP skill endpoints. Data sent to cognitive skills during indexing is transmitted in plaintext.`,
              'HIGH',
              { service: name, resourceGroup: rg, affectedSkillsets: httpSkillsets.map((s: any) => s.name) },
              'Update all custom skill endpoints to HTTPS URLs. Ensure cognitive service endpoints referenced in skillsets use HTTPS.',
              ['search', 'encryption-in-transit'],
            ));
          }
        } catch { /* optional — skillsets API not in ARM client */ }

        // 4. No private endpoint
        const peConns = svc.privateEndpointConnections ?? [];
        if (peConns.length === 0 && publicAccess === 'enabled') {
          findings.push(this.finding(
            'Azure AI Search service has no private endpoint configured',
            `AI Search service "${name}" has no private endpoint. Query and indexing traffic traverses public internet infrastructure.`,
            'MEDIUM',
            { service: name, resourceGroup: rg },
            'Create a Private Endpoint in the application VNet and disable public network access on the service.',
            ['search', 'network', 'private-endpoint'],
          ));
        }

        // 5. Customer-managed key (CMK)
        const encryptionKey = (svc as any).encryptionWithCmk;
        if (!encryptionKey || encryptionKey.enforcement !== 'Enabled') {
          findings.push(this.finding(
            'Azure AI Search service does not enforce customer-managed key encryption',
            `AI Search service "${name}" does not require customer-managed keys for index encryption. Search indexes may store sensitive documents without customer-controlled encryption.`,
            'MEDIUM',
            { service: name, resourceGroup: rg },
            'Enable CMK enforcement on the Search service and configure all indexes, synonymmaps, and indexers to use a customer-managed key from Azure Key Vault.',
            ['search', 'encryption', 'cmk'],
          ));
        }

        // 6. Managed identity not assigned
        const hasManagedIdentity = svc.identity?.type &&
          (svc.identity.type.includes('SystemAssigned') || svc.identity.type.includes('UserAssigned'));
        if (!hasManagedIdentity) {
          findings.push(this.finding(
            'Azure AI Search service has no managed identity assigned',
            `AI Search service "${name}" has no managed identity. Without managed identity, indexer connections to data sources (Storage, SQL, CosmosDB) require storing credentials in connection strings.`,
            'MEDIUM',
            { service: name, resourceGroup: rg },
            'Enable system-assigned managed identity on the Search service. Grant it access to data source resources (e.g., Storage Blob Data Reader) and configure indexer data source connections to use managed identity.',
            ['search', 'identity'],
          ));
        }

        // 7. IP firewall rules — check for open access
        const networkRuleSet = svc.networkRuleSet;
        const ipRules = networkRuleSet?.ipRules ?? [];
        if (ipRules.length === 0 && publicAccess === 'enabled') {
          findings.push(this.finding(
            'Azure AI Search service has no IP firewall rules configured',
            `AI Search service "${name}" has public access enabled with no IP firewall restrictions. Any internet host with a valid API key can query search indexes or trigger indexer runs.`,
            'HIGH',
            { service: name, resourceGroup: rg },
            'Add IP firewall rules to restrict access to the Search service to known application server IPs and the Azure Portal IP range. Or disable public access entirely.',
            ['search', 'network', 'firewall'],
          ));
        }

        // 8. Free tier — no SLA or network controls
        if (sku === 'free') {
          findings.push(this.finding(
            'Azure AI Search service is using the Free tier',
            `AI Search service "${name}" uses the Free tier which has no SLA, no IP firewall, no private endpoint support, and no CMK encryption. Not suitable for production use.`,
            'MEDIUM',
            { service: name, resourceGroup: rg, sku },
            'Upgrade to Basic or Standard tier for SLA guarantees and security controls including IP filtering and private endpoints.',
            ['search', 'sku'],
          ));
        }

        // 9. Diagnostic logs
        try {
          const monitorClient = this.client.monitor();
          const settingsResult = await monitorClient.diagnosticSettings.list(svc.id!);
          const settings: any[] = settingsResult.value ?? [];
          const hasLogs = settings.some(s =>
            s.logs?.some((l: any) => l.enabled) || s.metrics?.some((m: any) => m.enabled),
          );
          if (!hasLogs) {
            findings.push(this.finding(
              'Azure AI Search service has no diagnostic logs configured',
              `AI Search service "${name}" has no diagnostic settings. Without logs, query patterns, indexing failures, and throttling events cannot be monitored.`,
              'MEDIUM',
              { service: name, resourceGroup: rg },
              'Enable diagnostic settings to capture OperationLogs and send to Log Analytics for query performance analysis and anomaly detection.',
              ['search', 'logging'],
            ));
          }
        } catch { /* optional */ }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure AI Search scan error',
        `Could not complete AI Search scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Azure AI Search resources.',
      ));
    }

    return findings;
  }
}
