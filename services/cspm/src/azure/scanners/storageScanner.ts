// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
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

          // Blob versioning (storage_blob_versioning_is_enabled)
          if (!props.isVersioningEnabled) {
            findings.push(this.emit(
              'storage_blob_versioning_is_enabled',
              { account: name, resourceGroup: rg },
              { message: `Storage account "${name}" does not have blob versioning enabled. Previous versions of blobs created by updates or deletes are not automatically retained.` },
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

        // Public network access (storage_account_public_network_access_disabled)
        // Independent of the blob-public-access setting above.
        if (sa.publicNetworkAccess !== 'Disabled') {
          findings.push(this.emit(
            'storage_account_public_network_access_disabled',
            { account: name, resourceGroup: rg, publicNetworkAccess: sa.publicNetworkAccess ?? 'Enabled' },
            { message: `Storage account "${name}" does not have public network access disabled. The account can be reached from public networks unless overridden by private endpoints or trusted services.` },
          ));
        }

        // Cross-tenant replication (storage_cross_tenant_replication_disabled)
        if (sa.allowCrossTenantReplication !== false) {
          findings.push(this.emit(
            'storage_cross_tenant_replication_disabled',
            { account: name, resourceGroup: rg },
            { message: `Storage account "${name}" allows cross-tenant object replication. Replication policies are not restricted to the same tenant.` },
          ));
        }

        // Default to Entra authorization (storage_default_to_entra_authorization_enabled)
        if (!sa.defaultToOAuthAuthentication) {
          findings.push(this.emit(
            'storage_default_to_entra_authorization_enabled',
            { account: name, resourceGroup: rg },
            { message: `Storage account "${name}" does not default to Microsoft Entra authorization in the Azure portal. Clients default to account-key based access.` },
          ));
        }

        // Trusted Azure services bypass (storage_ensure_azure_services_are_trusted_to_access_is_enabled)
        const bypass: string = sa.networkRuleSet?.bypass ?? '';
        if (!bypass.includes('AzureServices')) {
          findings.push(this.emit(
            'storage_ensure_azure_services_are_trusted_to_access_is_enabled',
            { account: name, resourceGroup: rg, bypass },
            { message: `Storage account "${name}" does not allow trusted Microsoft services to bypass network rules. Platform services (e.g. backup, diagnostics) may be unable to reach the account when the firewall is restricted.` },
          ));
        }

        // Geo-redundant replication (storage_geo_redundant_enabled)
        const replication = sa.sku?.name ?? '';
        const geoRedundantSkus = ['Standard_GRS', 'Standard_GZRS', 'Standard_RAGRS', 'Standard_RAGZRS'];
        if (!geoRedundantSkus.includes(replication)) {
          findings.push(this.emit(
            'storage_geo_redundant_enabled',
            { account: name, resourceGroup: rg, replication: replication || 'unknown' },
            { message: `Storage account "${name}" does not use geo-redundant replication (has "${replication || 'unknown'}" instead). Data is not copied to a paired secondary region.` },
          ));
        }

        // Key rotation policy (storage_key_rotation_90_days)
        const keyExpirationDays: number | undefined = sa.keyPolicy?.keyExpirationPeriodInDays;
        if (!keyExpirationDays || keyExpirationDays > 90) {
          findings.push(this.emit(
            'storage_key_rotation_90_days',
            { account: name, resourceGroup: rg, keyExpirationPeriodInDays: keyExpirationDays ?? null },
            {
              message: keyExpirationDays
                ? `Storage account "${name}" has an access key expiration period of ${keyExpirationDays} days, exceeding the 90-day maximum.`
                : `Storage account "${name}" has no access key expiration period set, so keys are never flagged for rotation.`,
            },
          ));
        }

        // File-service checks: soft delete for file shares, SMB protocol version
        try {
          const fileProps = await storageClient.fileServices.getServiceProperties(rg, name);

          if (!fileProps.shareDeleteRetentionPolicy?.enabled) {
            findings.push(this.emit(
              'storage_ensure_file_shares_soft_delete_is_enabled',
              { account: name, resourceGroup: rg },
              { message: `Storage account "${name}" does not have soft delete enabled for file shares. Accidentally deleted file shares cannot be recovered.` },
            ));
          }

          const smbVersions = fileProps.protocolSettings?.smb?.versions;
          if (smbVersions) {
            const versionList = smbVersions.split(';').map((v: string) => v.trim()).filter(Boolean);
            if (versionList.length !== 1 || versionList[0] !== 'SMB3.1.1') {
              findings.push(this.emit(
                'storage_smb_protocol_version_is_latest',
                { account: name, resourceGroup: rg, smbVersions: versionList },
                { message: `Storage account "${name}" allows SMB protocol versions: ${versionList.join(', ') || 'none configured'}. Only the latest version (SMB3.1.1) should be allowed for file shares.` },
              ));
            }
          }
        } catch { /* file service properties not applicable to this account kind */ }
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
