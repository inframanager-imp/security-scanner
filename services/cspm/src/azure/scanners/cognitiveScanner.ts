import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

// Covers: Azure Cognitive Services, Azure OpenAI, Azure AI Foundry (AI Services kind)
export class AzureCognitiveScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-CognitiveServices');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const cogClient = this.client.cognitiveServices();

      const accounts: any[] = [];
      for await (const acct of cogClient.accounts.list()) accounts.push(acct);

      if (accounts.length === 0) return findings;

      for (const acct of accounts) {
        const name = acct.name ?? 'unknown';
        const rg   = acct.id?.split('/')[4] ?? 'unknown';
        const kind = acct.kind ?? 'unknown';  // 'OpenAI', 'CognitiveServices', 'AIServices', etc.
        const sku  = acct.sku?.name ?? 'unknown';

        // 1. Public network access enabled
        const publicAccess = acct.properties?.publicNetworkAccess ?? 'Enabled';
        if (publicAccess === 'Enabled') {
          findings.push(this.finding(
            'Cognitive Services / AI account has public network access enabled',
            `${kind} account "${name}" is accessible from the public internet. API keys exposed in client applications or logs can be exploited to consume AI services, exfiltrate data, or generate costs.`,
            'HIGH',
            { account: name, kind, resourceGroup: rg, sku },
            'Set publicNetworkAccess to "Disabled" and use Private Endpoint to restrict access to authorized VNet consumers. Apply IP network rules if private endpoint is not immediately feasible.',
            ['cognitiveservices', 'network', 'public-access'],
          ));
        }

        // 2. Network ACL — check for open access (no rules, default allow)
        const networkAcl = acct.properties?.networkAcls;
        const aclAction = networkAcl?.defaultAction ?? 'Allow';
        if (aclAction === 'Allow') {
          const hasIpRules = (networkAcl?.ipRules ?? []).length > 0;
          const hasVnetRules = (networkAcl?.virtualNetworkRules ?? []).length > 0;
          if (!hasIpRules && !hasVnetRules && publicAccess === 'Enabled') {
            findings.push(this.finding(
              'Cognitive Services / AI account has no network access restrictions',
              `${kind} account "${name}" has no IP rules or VNet rules configured. Any host with a valid API key can make requests from anywhere on the internet.`,
              'HIGH',
              { account: name, kind, resourceGroup: rg, defaultAction: aclAction },
              'Configure network ACL rules to restrict access to specific IP ranges or VNet subnets, or disable public access and use Private Endpoint.',
              ['cognitiveservices', 'network', 'acl'],
            ));
          }
        }

        // 3. Managed Identity — prefer over API key access
        const hasManagedIdentity = acct.identity?.type &&
          (acct.identity.type === 'SystemAssigned' ||
           acct.identity.type === 'UserAssigned' ||
           acct.identity.type === 'SystemAssigned,UserAssigned');
        if (!hasManagedIdentity) {
          findings.push(this.finding(
            'Cognitive Services / AI account has no managed identity assigned',
            `${kind} account "${name}" has no managed identity. Without managed identity, access to other Azure resources (Key Vault, Storage) requires storing credentials or connection strings in application config.`,
            'MEDIUM',
            { account: name, kind, resourceGroup: rg },
            'Assign a system-assigned managed identity to the account. Use it to grant the account access to Key Vault (for CMK) and to other Azure services without embedding credentials.',
            ['cognitiveservices', 'identity'],
          ));
        }

        // 4. Customer-managed key (CMK) not configured
        const encryptionKeySource = acct.properties?.encryption?.keySource ?? 'Microsoft.CognitiveServices';
        if (encryptionKeySource !== 'Microsoft.KeyVault') {
          findings.push(this.finding(
            'Cognitive Services / AI account does not use a customer-managed encryption key',
            `${kind} account "${name}" uses Microsoft-managed keys for encryption. Customer-managed keys (CMK) give you control over key lifecycle, rotation, and revocation.`,
            'MEDIUM',
            { account: name, kind, resourceGroup: rg, keySource: encryptionKeySource },
            'Configure encryption with a customer-managed key stored in Azure Key Vault. This requires a system-assigned managed identity with Key Vault access.',
            ['cognitiveservices', 'encryption', 'cmk'],
          ));
        }

        // 5. Diagnostic logs not configured
        try {
          const monitorClient = this.client.monitor();
          const settingsResult = await monitorClient.diagnosticSettings.list(acct.id!);
          const settings: any[] = settingsResult.value ?? [];
          const hasLogs = settings.some(s =>
            s.logs?.some((l: any) => l.enabled) || s.metrics?.some((m: any) => m.enabled),
          );
          if (!hasLogs) {
            findings.push(this.finding(
              'Cognitive Services / AI account has no diagnostic logs configured',
              `${kind} account "${name}" has no diagnostic settings. Without logs, API usage anomalies, unauthorized access attempts, and cost overruns cannot be detected.`,
              'MEDIUM',
              { account: name, kind, resourceGroup: rg },
              'Enable diagnostic settings to capture Audit and Request/Response logs and send them to a Log Analytics workspace.',
              ['cognitiveservices', 'logging'],
            ));
          }
        } catch { /* optional */ }

        // 6. Private endpoint not configured when public access is on
        try {
          const peConns = acct.properties?.privateEndpointConnections ?? [];
          if (peConns.length === 0 && publicAccess === 'Enabled') {
            findings.push(this.finding(
              'Cognitive Services / AI account has no private endpoint configured',
              `${kind} account "${name}" has no private endpoint. All API traffic traverses public internet infrastructure even if the consumer is within a VNet.`,
              'LOW',
              { account: name, kind, resourceGroup: rg },
              'Create a Private Endpoint in the application VNet for this Cognitive Services account and disable public network access.',
              ['cognitiveservices', 'network', 'private-endpoint'],
            ));
          }
        } catch { /* optional */ }

        // 7. Azure OpenAI — content filtering disabled
        if (kind === 'OpenAI' || kind === 'AIServices') {
          // Content filters are deployment-level; check if deployments have custom content filter with all categories set to allow
          try {
            const deployments: any[] = [];
            for await (const dep of cogClient.deployments.list(rg, name)) deployments.push(dep);

            for (const dep of deployments) {
              const contentFilter = dep.properties?.raiPolicyName;
              if (!contentFilter || contentFilter === 'Microsoft.Default') {
                // No custom RAI policy — using default (acceptable) but flag if set to none/disabled
                const filterMode = (dep.properties as any)?.contentFilter;
                if (filterMode === 'Disabled' || filterMode === 'None') {
                  findings.push(this.finding(
                    'Azure OpenAI deployment has content filtering disabled',
                    `Azure OpenAI deployment "${dep.name}" in account "${name}" has content filtering disabled. Without content filters, the model may generate harmful, biased, or non-compliant content.`,
                    'HIGH',
                    { account: name, deployment: dep.name, resourceGroup: rg },
                    'Enable content filtering on the OpenAI deployment using an appropriate Responsible AI (RAI) policy. Configure category-specific thresholds for hate, violence, sexual, and self-harm content.',
                    ['cognitiveservices', 'openai', 'content-filtering'],
                  ));
                }
              }
            }
          } catch { /* optional */ }
        }

        // 8. Outbound network restrictions (AI Foundry / AIServices)
        if (kind === 'AIServices') {
          const restrictOutbound = (acct.properties as any)?.restrictOutboundNetworkAccess;
          if (restrictOutbound === false || restrictOutbound === undefined) {
            findings.push(this.finding(
              'Azure AI Foundry account does not restrict outbound network access',
              `AI Services account "${name}" does not restrict outbound network access. AI workloads running within the account may make arbitrary outbound connections, enabling data exfiltration.`,
              'MEDIUM',
              { account: name, kind, resourceGroup: rg },
              'Enable restrictOutboundNetworkAccess and configure allowedFqdnList to permit only necessary outbound endpoints.',
              ['cognitiveservices', 'ai-foundry', 'network'],
            ));
          }
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Cognitive Services scan error',
        `Could not complete Cognitive Services / AI account scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Cognitive Services resources.',
      ));
    }

    return findings;
  }
}
