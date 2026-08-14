// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
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
          findings.push(this.emit(
            'azure_cosmosdb_public_network_access_disabled',
            { account: name, resourceGroup: rg },
            {
              message: `CosmosDB account "${name}" has publicNetworkAccess set to "Enabled". The data plane endpoint is reachable from the public internet.`,
            },
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
          findings.push(this.emit(
            'azure_cosmosdb_firewall_rules_configured',
            { account: name, resourceGroup: rg },
            {
              message: `CosmosDB account "${name}" has no IP firewall rules and no virtual network rules configured. Any client on the internet can attempt to authenticate to the account.`,
            },
          ));
        }

        // cosmosdb_account_firewall_use_selected_networks — VNet filter should be enabled
        if (!acct.isVirtualNetworkFilterEnabled) {
          findings.push(this.emit(
            'cosmosdb_account_firewall_use_selected_networks',
            { account: name, resourceGroup: rg },
            {
              message: `CosmosDB account "${name}" does not have virtual network filtering enabled, so firewall access is not restricted to selected networks.`,
            },
          ));
        }

        // 3. networkAclBypass — AzureServices grants all Azure services access regardless of firewall
        if (acct.networkAclBypass === 'AzureServices') {
          findings.push(this.emit(
            'azure_cosmosdb_network_acl_bypass_restricted',
            { account: name, resourceGroup: rg },
            {
              message: `CosmosDB account "${name}" has networkAclBypass set to "AzureServices". This allows any Azure service in any tenant to bypass the IP firewall, which is overly broad.`,
            },
          ));
        }

        // 4. Local (key-based) authentication — disableLocalAuth should be true
        if (acct.disableLocalAuth !== true) {
          findings.push(this.emit(
            'cosmosdb_account_use_aad_and_rbac',
            { account: name, resourceGroup: rg },
            {
              message: `CosmosDB account "${name}" has local authentication enabled. Primary/secondary account keys provide unrestricted data plane access and cannot be scoped to specific databases or operations.`,
            },
          ));
        }

        // 5. Automatic failover disabled (availability / resilience)
        if (!acct.enableAutomaticFailover) {
          findings.push(this.emit(
            'azure_cosmosdb_automatic_failover_enabled',
            { account: name, resourceGroup: rg },
            {
              message: `CosmosDB account "${name}" does not have automatic failover configured. If the primary region becomes unavailable, a manual failover is required, increasing RTO.`,
            },
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
              findings.push(this.emit(
                'azure_cosmosdb_backup_interval_sufficient',
                { account: name, resourceGroup: rg, backupIntervalHours: intervalHours },
                {
                  message: `CosmosDB account "${name}" has a periodic backup interval of ${intervalHours}h. Data loss window (RPO) is greater than 24 hours.`,
                },
              ));
            }
            if (retentionHours !== null && retentionHours < 168) { // less than 7 days
              findings.push(this.emit(
                'azure_cosmosdb_backup_retention_sufficient',
                { account: name, resourceGroup: rg, retentionHours },
                {
                  message: `CosmosDB account "${name}" retains backups for only ${retentionHours}h (${(retentionHours / 24).toFixed(1)} days). This may be insufficient for detecting and recovering from data corruption.`,
                },
              ));
            }
          }

          // cosmosdb_account_backup_policy_continuous
          if (backup.type !== 'Continuous') {
            findings.push(this.emit(
              'cosmosdb_account_backup_policy_continuous',
              { account: name, resourceGroup: rg, backupType: backup.type },
              {
                message: `CosmosDB account "${name}" uses "${backup.type}" backup policy instead of Continuous. Continuous backup enables point-in-time restore and reduces data-loss risk.`,
              },
            ));
          }
        } else {
          findings.push(this.emit(
            'cosmosdb_account_backup_policy_continuous',
            { account: name, resourceGroup: rg },
            {
              message: `CosmosDB account "${name}" has no backup policy returned by the API. Backup status cannot be verified.`,
              severity: 'INFO',
            },
          ));
        }

        // cosmosdb_account_minimum_tls_version
        const tlsVersion = acct.minimalTlsVersion;
        if (tlsVersion !== 'Tls12' && tlsVersion !== 'Tls13') {
          findings.push(this.emit(
            'cosmosdb_account_minimum_tls_version',
            { account: name, resourceGroup: rg, minimalTlsVersion: tlsVersion ?? 'unset' },
            {
              message: `CosmosDB account "${name}" does not enforce TLS 1.2 or higher (minimalTlsVersion: "${tlsVersion ?? 'unset'}").`,
            },
          ));
        }

        // cosmosdb_account_use_private_endpoints
        if (!(acct.privateEndpointConnections ?? []).length) {
          findings.push(this.emit(
            'cosmosdb_account_use_private_endpoints',
            { account: name, resourceGroup: rg },
            {
              message: `CosmosDB account "${name}" is not using Private Endpoint connections. Access relies on the public data-plane endpoint rather than private network isolation.`,
            },
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
