import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureKeyVaultScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-KeyVault');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const kvClient = this.client.keyVault();

    try {
      const vaults: any[] = [];
      for await (const v of kvClient.vaults.listBySubscription()) vaults.push(v);

      for (const vault of vaults) {
        const name = vault.name ?? 'unknown';
        const rg   = vault.id?.split('/')[4] ?? 'unknown';
        const props = vault.properties;

        // Soft delete disabled
        if (!props?.enableSoftDelete) {
          findings.push(this.emit(
            'azure_keyvault_soft_delete_enabled',
            { vault: name, resourceGroup: rg },
            { message: `Key Vault "${name}" does not have soft delete enabled. Deleted secrets, keys, and certificates cannot be recovered.` },
          ));
        }

        // Purge protection disabled
        if (!props?.enablePurgeProtection) {
          findings.push(this.emit(
            'keyvault_recoverable',
            { vault: name, resourceGroup: rg },
            { message: `Key Vault "${name}" does not have purge protection enabled. Even with soft delete, a privileged user can permanently delete vaulted secrets during the retention window.` },
          ));
        }

        // Public network access allowed
        const networkAcls = props?.networkAcls;
        const defaultAction = networkAcls?.defaultAction ?? 'Allow';
        if (defaultAction === 'Allow') {
          findings.push(this.emit(
            'azure_keyvault_network_access_restricted',
            { vault: name, resourceGroup: rg },
            { message: `Key Vault "${name}" network ACL default action is "Allow", meaning any IP address can attempt to access it.` },
          ));
        }

        // RBAC authorization vs access policies
        const rbacEnabled = props?.enableRbacAuthorization ?? false;
        if (!rbacEnabled) {
          findings.push(this.emit(
            'keyvault_rbac_enabled',
            { vault: name, resourceGroup: rg },
            { message: `Key Vault "${name}" uses the legacy vault access policy model instead of Azure RBAC. Access policies cannot be audited with the same granularity as RBAC assignments.` },
          ));
        }

        // Diagnostic logging
        // (ARM doesn't expose this directly — flag as informational)
        findings.push(this.emit(
          'keyvault_logging_enabled',
          { vault: name, resourceGroup: rg },
          { message: `Key Vault "${name}" diagnostic logging should be verified. All access to secrets, keys, and certificates should be logged to a Log Analytics workspace or Storage account.`, severity: 'INFO' },
        ));
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Key Vault scan error',
        `Could not complete Key Vault scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Key Vault Contributor or Reader permissions.',
      ));
    }

    return findings;
  }
}
