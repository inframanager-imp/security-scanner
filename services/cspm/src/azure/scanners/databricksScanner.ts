// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';
import type { AzureClient } from '../client';

export class AzureDatabricksScanner extends AzureBaseScanner {
  constructor(client: AzureClient) {
    super(client, 'Azure-Databricks');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const databricksClient = this.client.databricks();

      const workspaces: any[] = [];
      for await (const ws of databricksClient.workspaces.listBySubscription()) workspaces.push(ws);

      if (workspaces.length === 0) return findings;

      for (const ws of workspaces) {
        const name = ws.name ?? 'unknown';
        const rg   = ws.id?.split('/')[4] ?? 'unknown';

        // databricks_workspace_cmk_encryption_enabled: managed-disk encryption
        // should use a customer-managed key (via Key Vault) rather than a
        // provider-controlled key.
        const managedDiskEncryption = ws.encryption?.entities?.managedDisk;
        const keyVaultProps = managedDiskEncryption?.keyVaultProperties;
        if (keyVaultProps) {
          // Encrypted with CMK — no finding.
        } else {
          findings.push(this.emit(
            'databricks_workspace_cmk_encryption_enabled',
            { workspace: name, resourceGroup: rg, workspaceId: ws.id },
            {
              message: `Databricks workspace "${name}" does not have customer-managed key (CMK) encryption enabled for managed disks`,
            },
          ));
        }

        // databricks_workspace_no_public_ip_enabled: classic-compute cluster
        // nodes should not be assigned public IP addresses. Serverless
        // workspaces don't expose this setting — treat as informational, not FAIL.
        const noPublicIpParam = ws.parameters?.enableNoPublicIp;
        const noPublicIpEnabled: boolean | undefined = noPublicIpParam ? noPublicIpParam.value : undefined;
        if (noPublicIpEnabled === undefined) {
          findings.push(this.emit(
            'databricks_workspace_no_public_ip_enabled',
            { workspace: name, resourceGroup: rg, workspaceId: ws.id },
            {
              message: `Databricks workspace "${name}" does not expose secure cluster connectivity (no public IP) settings (for example, serverless workspaces have no public-IP cluster nodes); verify the network configuration manually`,
              severity: 'INFO',
            },
          ));
        } else if (noPublicIpEnabled === false) {
          findings.push(this.emit(
            'databricks_workspace_no_public_ip_enabled',
            { workspace: name, resourceGroup: rg, workspaceId: ws.id, noPublicIpEnabled },
            {
              message: `Databricks workspace "${name}" does not have secure cluster connectivity (no public IP) enabled — cluster nodes may be assigned public IP addresses`,
            },
          ));
        }

        // databricks_workspace_public_network_access_disabled
        const publicNetworkAccess = ws.publicNetworkAccess;
        if (publicNetworkAccess !== 'Disabled') {
          findings.push(this.emit(
            'databricks_workspace_public_network_access_disabled',
            { workspace: name, resourceGroup: rg, workspaceId: ws.id, publicNetworkAccess },
            {
              message: `Databricks workspace "${name}" has public network access enabled, exposing the control plane and data plane to the internet`,
            },
          ));
        }

        // databricks_workspace_vnet_injection_enabled
        const customVnetId = ws.parameters?.customVirtualNetworkId?.value;
        if (!customVnetId) {
          findings.push(this.emit(
            'databricks_workspace_vnet_injection_enabled',
            { workspace: name, resourceGroup: rg, workspaceId: ws.id },
            {
              message: `Databricks workspace "${name}" is not deployed in a customer-managed VNet (VNet injection is not enabled)`,
            },
          ));
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Databricks scan error',
        `Could not complete Databricks workspace scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Databricks workspace resources.',
      ));
    }

    return findings;
  }
}

export default AzureDatabricksScanner;
