// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
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
        const hasPrivateEndpoints = (props?.privateEndpointConnections ?? []).length > 0;

        // Soft delete disabled
        if (!props?.enableSoftDelete) {
          findings.push(this.emit(
            'azure_keyvault_soft_delete_enabled',
            { vault: name, resourceGroup: rg },
            {
              message: `Key Vault "${name}" does not have soft delete enabled. Deleted secrets, keys, and certificates cannot be recovered.`,
            },
          ));
        }

        // Soft delete + purge protection together (keyvault_recoverable)
        if (!props?.enableSoftDelete || !props?.enablePurgeProtection) {
          findings.push(this.emit(
            'keyvault_recoverable',
            { vault: name, resourceGroup: rg, softDelete: !!props?.enableSoftDelete, purgeProtection: !!props?.enablePurgeProtection },
            {
              message: `Key Vault "${name}" is not fully recoverable: soft delete is ${props?.enableSoftDelete ? 'enabled' : 'disabled'} and purge protection is ${props?.enablePurgeProtection ? 'enabled' : 'disabled'}. Even with soft delete alone, a privileged user can permanently purge vaulted secrets during the retention window.`,
            },
          ));
        }

        // Public network access allowed
        const networkAcls = props?.networkAcls;
        const defaultAction = networkAcls?.defaultAction ?? 'Allow';
        if (defaultAction === 'Allow') {
          findings.push(this.emit(
            'azure_keyvault_network_access_restricted',
            { vault: name, resourceGroup: rg },
            {
              message: `Key Vault "${name}" network ACL default action is "Allow", meaning any IP address can attempt to access it.`,
            },
          ));
        }

        // RBAC authorization vs access policies
        const rbacEnabled = props?.enableRbacAuthorization ?? false;
        if (!rbacEnabled) {
          findings.push(this.emit(
            'keyvault_rbac_enabled',
            { vault: name, resourceGroup: rg },
            {
              message: `Key Vault "${name}" uses the legacy vault access policy model instead of Azure RBAC. Access policies cannot be audited with the same granularity as RBAC assignments.`,
            },
          ));
        }

        // Private endpoints (keyvault_private_endpoints)
        if (!hasPrivateEndpoints) {
          findings.push(this.emit(
            'keyvault_private_endpoints',
            { vault: name, resourceGroup: rg },
            {
              message: `Key Vault "${name}" is not using Private Endpoints. Access relies on the public service endpoint or network ACLs rather than private network isolation.`,
            },
          ));
        } else {
          // keyvault_access_only_through_private_endpoints — for vaults with a
          // private endpoint, public network access should be disabled entirely.
          const publicAccessDisabled = props?.publicNetworkAccess === 'Disabled';
          if (!publicAccessDisabled) {
            findings.push(this.emit(
              'keyvault_access_only_through_private_endpoints',
              { vault: name, resourceGroup: rg },
              {
                message: `Key Vault "${name}" has Private Endpoint(s) configured but public network access is not disabled, so the vault remains reachable over the public internet as well.`,
              },
            ));
          }
        }

        // Diagnostic / audit logging (keyvault_logging_enabled)
        try {
          const monitorClient = this.client.monitor();
          const settingsResult = await monitorClient.diagnosticSettings.list(vault.id!);
          const settings: any[] = settingsResult.value ?? [];
          const hasAuditLogging = settings.some(s =>
            (s.logs ?? []).some((l: any) => l.category === 'AuditEvent' && l.enabled),
          );
          if (!hasAuditLogging) {
            findings.push(this.emit(
              'keyvault_logging_enabled',
              { vault: name, resourceGroup: rg },
              {
                message: `Key Vault "${name}" does not have a diagnostic setting with AuditEvent logging enabled. Access to secrets, keys, and certificates is not being recorded to a Log Analytics workspace or storage account.`,
              },
            ));
          }
        } catch { /* diagnostic settings check optional */ }

        // Key rotation + expiration (keyvault_key_rotation_enabled, azure_keyvault_key_expiration_set)
        try {
          const keys: any[] = [];
          for await (const key of kvClient.keys.list(rg, name)) keys.push(key);

          for (const key of keys) {
            if (key.attributes?.enabled === false) continue;
            const keyName = key.name ?? 'unknown';

            const hasRotationPolicy = (key.rotationPolicy?.lifetimeActions ?? []).some(
              (action: any) => action.action === 'Rotate',
            );
            if (!hasRotationPolicy) {
              findings.push(this.emit(
                'keyvault_key_rotation_enabled',
                { vault: name, resourceGroup: rg, key: keyName },
                {
                  message: `Key "${keyName}" in Key Vault "${name}" does not have an automatic rotation policy configured.`,
                },
              ));
            }

            if (!key.attributes?.expires) {
              findings.push(this.emit(
                'azure_keyvault_key_expiration_set',
                { vault: name, resourceGroup: rg, key: keyName },
                {
                  message: `Key "${keyName}" in Key Vault "${name}" does not have an expiration date set.`,
                },
              ));
            }
          }
        } catch { /* keys listing optional — may require additional RBAC */ }

        // Secret expiration (azure_keyvault_secret_expiration_set)
        try {
          const secrets: any[] = [];
          for await (const secret of kvClient.secrets.list(rg, name)) secrets.push(secret);

          for (const secret of secrets) {
            if (secret.attributes?.enabled === false) continue;
            const secretName = secret.name ?? 'unknown';
            if (!secret.attributes?.expires) {
              findings.push(this.emit(
                'azure_keyvault_secret_expiration_set',
                { vault: name, resourceGroup: rg, secret: secretName },
                {
                  message: `Secret "${secretName}" in Key Vault "${name}" does not have an expiration date set.`,
                },
              ));
            }
          }
        } catch { /* secrets listing optional — may require additional RBAC */ }
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
