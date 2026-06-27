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
          findings.push(this.finding(
            'Key Vault soft delete is disabled',
            `Key Vault "${name}" does not have soft delete enabled. Deleted secrets, keys, and certificates cannot be recovered.`,
            'HIGH',
            { vault: name, resourceGroup: rg },
            'Enable soft delete with a retention of at least 7 days. Once enabled, soft delete cannot be disabled.',
            ['keyvault', 'data-protection'],
          ));
        }

        // Purge protection disabled
        if (!props?.enablePurgeProtection) {
          findings.push(this.finding(
            'Key Vault purge protection is disabled',
            `Key Vault "${name}" does not have purge protection enabled. Even with soft delete, a privileged user can permanently delete vaulted secrets during the retention window.`,
            'HIGH',
            { vault: name, resourceGroup: rg },
            'Enable purge protection. This ensures deleted vault objects cannot be permanently removed until the retention period expires.',
            ['keyvault', 'data-protection'],
          ));
        }

        // Public network access allowed
        const networkAcls = props?.networkAcls;
        const defaultAction = networkAcls?.defaultAction ?? 'Allow';
        if (defaultAction === 'Allow') {
          findings.push(this.finding(
            'Key Vault is publicly accessible from all networks',
            `Key Vault "${name}" network ACL default action is "Allow", meaning any IP address can attempt to access it.`,
            'HIGH',
            { vault: name, resourceGroup: rg },
            'Set the network ACL default action to "Deny" and whitelist only known IP ranges or virtual networks. Consider using Private Endpoint.',
            ['keyvault', 'network'],
          ));
        }

        // RBAC authorization vs access policies
        const rbacEnabled = props?.enableRbacAuthorization ?? false;
        if (!rbacEnabled) {
          findings.push(this.finding(
            'Key Vault uses legacy access policies instead of Azure RBAC',
            `Key Vault "${name}" uses the legacy vault access policy model instead of Azure RBAC. Access policies cannot be audited with the same granularity as RBAC assignments.`,
            'MEDIUM',
            { vault: name, resourceGroup: rg },
            'Migrate Key Vault to Azure RBAC permission model for fine-grained, auditable access control.',
            ['keyvault', 'rbac'],
          ));
        }

        // Diagnostic logging
        // (ARM doesn't expose this directly — flag as informational)
        findings.push(this.finding(
          'Verify Key Vault diagnostic logging is enabled',
          `Key Vault "${name}" diagnostic logging should be verified. All access to secrets, keys, and certificates should be logged to a Log Analytics workspace or Storage account.`,
          'INFO',
          { vault: name, resourceGroup: rg },
          'Enable diagnostic settings for the Key Vault and send AuditEvent logs to a Log Analytics workspace with a minimum 90-day retention.',
          ['keyvault', 'logging'],
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
