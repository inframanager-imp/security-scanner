import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureStorageScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-Storage');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const storageClient = this.client.storage();

    try {
      const accounts: any[] = [];
      for await (const sa of storageClient.storageAccounts.list()) accounts.push(sa);

      for (const sa of accounts) {
        const name = sa.name ?? 'unknown';
        const rg   = sa.id?.split('/')[4] ?? 'unknown';

        // Public blob access enabled
        if (sa.allowBlobPublicAccess === true) {
          findings.push(this.finding(
            'Storage account allows public blob access',
            `Storage account "${name}" has allowBlobPublicAccess enabled. Any container/blob set to public will be accessible without authentication.`,
            'HIGH',
            { account: name, resourceGroup: rg },
            'Set allowBlobPublicAccess=false at the account level. Individual container-level public access settings will be ignored.',
            ['storage', 'public-access'],
          ));
        }

        // HTTPS-only not enforced
        if (!sa.enableHttpsTrafficOnly) {
          findings.push(this.finding(
            'Storage account allows HTTP traffic',
            `Storage account "${name}" does not enforce HTTPS-only access, allowing unencrypted data in transit.`,
            'HIGH',
            { account: name, resourceGroup: rg },
            'Enable the "Secure transfer required" (enableHttpsTrafficOnly) setting on all storage accounts.',
            ['storage', 'encryption-in-transit'],
          ));
        }

        // Minimum TLS version
        const tls = sa.minimumTlsVersion ?? 'TLS1_0';
        if (tls !== 'TLS1_2') {
          findings.push(this.finding(
            'Storage account uses weak minimum TLS version',
            `Storage account "${name}" has minimum TLS version "${tls}". TLS 1.0/1.1 are deprecated and vulnerable.`,
            'MEDIUM',
            { account: name, tlsVersion: tls, resourceGroup: rg },
            'Set minimumTlsVersion to TLS1_2 on all storage accounts.',
            ['storage', 'tls'],
          ));
        }

        // Infrastructure encryption (double encryption)
        if (!sa.encryption?.requireInfrastructureEncryption) {
          findings.push(this.finding(
            'Storage account lacks infrastructure encryption',
            `Storage account "${name}" does not have infrastructure (double) encryption enabled. Highly sensitive data should use both platform and infrastructure encryption layers.`,
            'LOW',
            { account: name, resourceGroup: rg },
            'Enable infrastructure encryption when creating storage accounts. Note: this cannot be changed after creation — recreate the account if required.',
            ['storage', 'encryption-at-rest'],
          ));
        }

        // Customer-managed keys
        const keySource = sa.encryption?.keySource ?? 'Microsoft.Storage';
        if (keySource !== 'Microsoft.Keyvault') {
          findings.push(this.finding(
            'Storage account not using customer-managed keys',
            `Storage account "${name}" is encrypted with Microsoft-managed keys. Customer-managed keys (CMK) via Key Vault provide greater control.`,
            'LOW',
            { account: name, keySource, resourceGroup: rg },
            'Configure customer-managed keys in Azure Key Vault for storage accounts holding sensitive data.',
            ['storage', 'cmk'],
          ));
        }

        // Blob soft delete
        try {
          const props = await storageClient.blobServices.getServiceProperties(rg, name);
          if (!props.deleteRetentionPolicy?.enabled) {
            findings.push(this.finding(
              'Storage account blob soft delete not enabled',
              `Storage account "${name}" does not have blob soft delete enabled. Accidental or malicious deletions cannot be recovered.`,
              'MEDIUM',
              { account: name, resourceGroup: rg },
              'Enable blob soft delete with a minimum retention of 7 days.',
              ['storage', 'data-protection'],
            ));
          }
        } catch { /* skip if blob service not applicable */ }

        // Shared key access (allows full access via account key)
        if (sa.allowSharedKeyAccess !== false) {
          findings.push(this.finding(
            'Storage account allows shared key (account key) access',
            `Storage account "${name}" permits authentication via account access keys, bypassing Azure AD RBAC and audit logs.`,
            'MEDIUM',
            { account: name, resourceGroup: rg },
            'Set allowSharedKeyAccess=false and migrate all access to Azure AD and SAS tokens with specific permissions.',
            ['storage', 'authentication'],
          ));
        }

        // Network ACL — default action should be Deny
        const networkDefaultAction = sa.networkRuleSet?.defaultAction ?? 'Allow';
        if (networkDefaultAction === 'Allow') {
          findings.push(this.finding(
            'Storage account network access not restricted',
            `Storage account "${name}" network ACL default action is "Allow", meaning any IP address on the internet can reach the storage endpoint (subject only to authentication).`,
            'HIGH',
            { account: name, resourceGroup: rg },
            'Set the storage account network ACL default action to "Deny" and add only required VNet rules or IP ranges. Use Private Endpoint for internal access.',
            ['storage', 'network', 'public-access'],
          ));
        }

        // Private endpoint
        try {
          const peps = await storageClient.privateEndpointConnections.list(rg, name);
          const pepList: any[] = [];
          for await (const pep of peps) pepList.push(pep);
          const hasApprovedPep = pepList.some(
            p => p.privateLinkServiceConnectionState?.status === 'Approved',
          );
          if (!hasApprovedPep && networkDefaultAction === 'Allow') {
            findings.push(this.finding(
              'Storage account has no private endpoint configured',
              `Storage account "${name}" has no approved private endpoint connection and network access is unrestricted. Traffic to the storage account travels over the public internet.`,
              'MEDIUM',
              { account: name, resourceGroup: rg },
              'Create a Private Endpoint for the storage account in each VNet that needs access, and restrict the network ACL default action to Deny.',
              ['storage', 'private-endpoint', 'network'],
            ));
          }
        } catch { /* private endpoint check optional */ }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Storage scan error',
        `Could not complete Storage scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Storage Account Contributor or Reader permissions.',
      ));
    }

    return findings;
  }
}
