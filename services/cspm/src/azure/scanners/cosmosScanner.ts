import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureCosmosScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-CosmosDB');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const cosmosClient = this.client.cosmos();

      const accounts: any[] = [];
      for await (const acct of cosmosClient.databaseAccounts.list()) accounts.push(acct);

      if (accounts.length === 0) return findings;

      for (const acct of accounts) {
        const name = acct.name ?? 'unknown';
        const rg   = acct.id?.split('/')[4] ?? 'unknown';

        // 1. Public network access
        if (acct.publicNetworkAccess === 'Enabled') {
          findings.push(this.finding(
            'CosmosDB account has public network access enabled',
            `CosmosDB account "${name}" has publicNetworkAccess set to "Enabled". The data plane endpoint is reachable from the public internet.`,
            'HIGH',
            { account: name, resourceGroup: rg },
            'Set publicNetworkAccess to "Disabled" and use Private Endpoint for connectivity. Update all application connection strings to use the private DNS FQDN.',
            ['cosmosdb', 'network', 'public-access'],
          ));
        }

        // 2. IP firewall — empty rules means open to all when public access is on
        const ipRules = acct.ipRules ?? [];
        const virtualNetworkRules = acct.virtualNetworkRules ?? [];
        if (
          acct.publicNetworkAccess !== 'Disabled' &&
          ipRules.length === 0 &&
          virtualNetworkRules.length === 0
        ) {
          findings.push(this.finding(
            'CosmosDB account has no IP or VNet firewall rules',
            `CosmosDB account "${name}" has no IP firewall rules and no virtual network rules configured. Any client on the internet can attempt to authenticate to the account.`,
            'HIGH',
            { account: name, resourceGroup: rg },
            'Add IP firewall rules restricting access to known application server IPs, or configure VNet service endpoints/Private Endpoint to eliminate public access entirely.',
            ['cosmosdb', 'firewall', 'network'],
          ));
        }

        // 3. networkAclBypass — AzureServices grants all Azure services access regardless of firewall
        if (acct.networkAclBypass === 'AzureServices') {
          findings.push(this.finding(
            'CosmosDB account allows all Azure services to bypass firewall',
            `CosmosDB account "${name}" has networkAclBypass set to "AzureServices". This allows any Azure service in any tenant to bypass the IP firewall, which is overly broad.`,
            'MEDIUM',
            { account: name, resourceGroup: rg },
            'Set networkAclBypass to "None" and explicitly allow only required Azure services (e.g. Azure Data Factory) via their managed identity or VNet integration.',
            ['cosmosdb', 'firewall', 'network'],
          ));
        }

        // 4. Local (key-based) authentication — disableLocalAuth should be true
        if (acct.disableLocalAuth !== true) {
          findings.push(this.finding(
            'CosmosDB account allows key-based (local) authentication',
            `CosmosDB account "${name}" has local authentication enabled. Primary/secondary account keys provide unrestricted data plane access and cannot be scoped to specific databases or operations.`,
            'MEDIUM',
            { account: name, resourceGroup: rg },
            'Set disableLocalAuth=true and migrate all clients to use Azure AD (RBAC) authentication with least-privilege roles (Cosmos DB Built-in Data Reader, etc.).',
            ['cosmosdb', 'authentication'],
          ));
        }

        // 5. Automatic failover disabled (availability / resilience)
        if (!acct.enableAutomaticFailover) {
          findings.push(this.finding(
            'CosmosDB account does not have automatic failover enabled',
            `CosmosDB account "${name}" does not have automatic failover configured. If the primary region becomes unavailable, a manual failover is required, increasing RTO.`,
            'LOW',
            { account: name, resourceGroup: rg },
            'Enable automatic failover and configure at least one additional write region to ensure high availability.',
            ['cosmosdb', 'availability'],
          ));
        }

        // 6. Backup policy — check for continuous vs periodic, and retention
        const backup = acct.backupPolicy;
        if (backup) {
          if (backup.type === 'Periodic') {
            const periodicProps = (backup as any).periodicModeProperties;
            const intervalHours = periodicProps?.backupIntervalInMinutes
              ? periodicProps.backupIntervalInMinutes / 60
              : null;
            const retentionHours = periodicProps?.backupRetentionIntervalInHours ?? null;
            if (intervalHours !== null && intervalHours > 24) {
              findings.push(this.finding(
                'CosmosDB account backup interval exceeds 24 hours',
                `CosmosDB account "${name}" has a periodic backup interval of ${intervalHours}h. Data loss window (RPO) is greater than 24 hours.`,
                'MEDIUM',
                { account: name, resourceGroup: rg, backupIntervalHours: intervalHours },
                'Reduce the backup interval to at most 4 hours. Consider migrating to Continuous backup mode for point-in-time restore capability.',
                ['cosmosdb', 'backup'],
              ));
            }
            if (retentionHours !== null && retentionHours < 168) { // less than 7 days
              findings.push(this.finding(
                'CosmosDB account backup retention is less than 7 days',
                `CosmosDB account "${name}" retains backups for only ${retentionHours}h (${(retentionHours / 24).toFixed(1)} days). This may be insufficient for detecting and recovering from data corruption.`,
                'LOW',
                { account: name, resourceGroup: rg, retentionHours },
                'Increase backup retention to at least 7 days (168 hours). For compliance workloads, consider 30 days.',
                ['cosmosdb', 'backup'],
              ));
            }
          }
        } else {
          findings.push(this.finding(
            'CosmosDB account backup policy not configured',
            `CosmosDB account "${name}" has no backup policy returned by the API. Backup status cannot be verified.`,
            'INFO',
            { account: name, resourceGroup: rg },
            'Verify backup is configured in the Azure Portal under the CosmosDB account > Backup & Restore settings.',
            ['cosmosdb', 'backup'],
          ));
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure CosmosDB scan error',
        `Could not complete CosmosDB scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on CosmosDB resources.',
      ));
    }

    return findings;
  }
}
