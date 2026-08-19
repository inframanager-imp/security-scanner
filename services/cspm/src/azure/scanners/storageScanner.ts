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
          findings.push(this.emit(
            'azure_storage_public_blob_access_disabled',
            { account: name, resourceGroup: rg },
            { message: `Storage account "${name}" has allowBlobPublicAccess enabled. Any container/blob set to public will be accessible without authentication.` },
          ));
        }

        // HTTPS-only not enforced
        if (!sa.enableHttpsTrafficOnly) {
          findings.push(this.emit(
            'azure_storage_https_only_enforced',
            { account: name, resourceGroup: rg },
            { message: `Storage account "${name}" does not enforce HTTPS-only access, allowing unencrypted data in transit.` },
          ));
        }

        // Minimum TLS version
        const tls = sa.minimumTlsVersion ?? 'TLS1_0';
        if (tls !== 'TLS1_2') {
          findings.push(this.emit(
            'azure_storage_minimum_tls_version_12',
            { account: name, tlsVersion: tls, resourceGroup: rg },
            { message: `Storage account "${name}" has minimum TLS version "${tls}". TLS 1.0/1.1 are deprecated and vulnerable.` },
          ));
        }

        // Infrastructure encryption (double encryption)
        if (!sa.encryption?.requireInfrastructureEncryption) {
          findings.push(this.emit(
            'azure_storage_infrastructure_encryption_enabled',
            { account: name, resourceGroup: rg },
            { message: `Storage account "${name}" does not have infrastructure (double) encryption enabled. Highly sensitive data should use both platform and infrastructure encryption layers.` },
          ));
        }

        // Customer-managed keys
        const keySource = sa.encryption?.keySource ?? 'Microsoft.Storage';
        if (keySource !== 'Microsoft.Keyvault') {
          findings.push(this.emit(
            'azure_storage_customer_managed_key_encryption',
            { account: name, keySource, resourceGroup: rg },
            { message: `Storage account "${name}" is encrypted with Microsoft-managed keys. Customer-managed keys (CMK) via Key Vault provide greater control.` },
          ));
        }

        // Blob soft delete
        try {
          const props = await storageClient.blobServices.getServiceProperties(rg, name);
          if (!props.deleteRetentionPolicy?.enabled) {
            findings.push(this.emit(
              'azure_storage_blob_soft_delete_enabled',
              { account: name, resourceGroup: rg },
              { message: `Storage account "${name}" does not have blob soft delete enabled. Accidental or malicious deletions cannot be recovered.` },
            ));
          }
        } catch { /* skip if blob service not applicable */ }

        // Shared key access (allows full access via account key)
        if (sa.allowSharedKeyAccess !== false) {
          findings.push(this.emit(
            'azure_storage_shared_key_access_disallowed',
            { account: name, resourceGroup: rg },
            { message: `Storage account "${name}" permits authentication via account access keys, bypassing Azure AD RBAC and audit logs.` },
          ));
        }

        // Network ACL — default action should be Deny
        const networkDefaultAction = sa.networkRuleSet?.defaultAction ?? 'Allow';
        if (networkDefaultAction === 'Allow') {
          findings.push(this.emit(
            'azure_storage_network_default_action_deny',
            { account: name, resourceGroup: rg },
            { message: `Storage account "${name}" network ACL default action is "Allow", meaning any IP address on the internet can reach the storage endpoint (subject only to authentication).` },
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
            findings.push(this.emit(
              'azure_storage_private_endpoint_configured',
              { account: name, resourceGroup: rg },
              { message: `Storage account "${name}" has no approved private endpoint connection and network access is unrestricted. Traffic to the storage account travels over the public internet.` },
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
