import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureMLScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-MachineLearning');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const amlClient = this.client.machineLearning();

      const workspaces: any[] = [];
      for await (const ws of amlClient.workspaces.listBySubscription()) workspaces.push(ws);

      if (workspaces.length === 0) return findings;

      for (const ws of workspaces) {
        const name = ws.name ?? 'unknown';
        const rg   = ws.id?.split('/')[4] ?? 'unknown';

        // 1. Public network access enabled
        const publicAccess = ws.publicNetworkAccess ?? 'Enabled';
        if (publicAccess === 'Enabled') {
          findings.push(this.finding(
            'Azure ML workspace has public network access enabled',
            `Machine Learning workspace "${name}" is accessible from the public internet. This exposes the workspace portal, experiments, and model endpoints to unauthorized access.`,
            'HIGH',
            { workspace: name, resourceGroup: rg, publicNetworkAccess: publicAccess },
            'Set publicNetworkAccess to "Disabled" and configure private endpoints for the workspace, associated storage, Key Vault, and Container Registry.',
            ['machinelearning', 'network', 'public-access'],
          ));
        }

        // 2. No managed VNet
        const managedNetwork = (ws as any).managedNetwork;
        const hasManagedVNet = managedNetwork?.isolationMode &&
          managedNetwork.isolationMode !== 'Disabled';
        if (!hasManagedVNet) {
          findings.push(this.finding(
            'Azure ML workspace has no managed network isolation',
            `Machine Learning workspace "${name}" does not use managed network isolation. ML training compute and deployments can make unrestricted outbound connections, enabling data exfiltration.`,
            'HIGH',
            { workspace: name, resourceGroup: rg },
            'Enable managed network isolation on the workspace with "AllowOnlyApprovedOutbound" mode and configure approved outbound rules for necessary external services.',
            ['machinelearning', 'network', 'isolation'],
          ));
        }

        // 3. Customer-managed key (CMK)
        const encryptionKeyId = ws.encryption?.keyVaultProperties?.keyIdentifier;
        if (!encryptionKeyId) {
          findings.push(this.finding(
            'Azure ML workspace does not use a customer-managed encryption key',
            `Machine Learning workspace "${name}" uses Microsoft-managed keys for encryption of workspace data, model artifacts, and experiments. Customer-managed keys give control over key lifecycle and revocation.`,
            'MEDIUM',
            { workspace: name, resourceGroup: rg },
            'Configure a customer-managed key (CMK) via an Azure Key Vault key identifier on the workspace encryption settings.',
            ['machinelearning', 'encryption', 'cmk'],
          ));
        }

        // 4. Managed identity not assigned
        const hasManagedIdentity = ws.identity?.type &&
          (ws.identity.type.includes('SystemAssigned') || ws.identity.type.includes('UserAssigned'));
        if (!hasManagedIdentity) {
          findings.push(this.finding(
            'Azure ML workspace has no managed identity assigned',
            `Machine Learning workspace "${name}" has no managed identity. Without managed identity, compute clusters and jobs cannot securely access Azure resources without embedding credentials.`,
            'MEDIUM',
            { workspace: name, resourceGroup: rg },
            'Enable system-assigned managed identity on the workspace and grant it access to the associated storage account, Key Vault, and Container Registry.',
            ['machinelearning', 'identity'],
          ));
        }

        // 5. High Business Impact (HBI) workspace — extra data controls
        if (ws.hbiWorkspace === false || ws.hbiWorkspace === undefined) {
          findings.push(this.finding(
            'Azure ML workspace is not configured as a High Business Impact workspace',
            `Machine Learning workspace "${name}" is not configured as a High Business Impact (HBI) workspace. HBI mode enables additional encryption of diagnostic logs and data at rest. Recommended when the workspace processes sensitive or regulated data.`,
            'LOW',
            { workspace: name, resourceGroup: rg, hbiWorkspace: ws.hbiWorkspace },
            'If this workspace processes sensitive data (PII, PHI, financial data), recreate it with hbiWorkspace=true to enable enhanced data encryption controls.',
            ['machinelearning', 'data-classification'],
          ));
        }

        // 6. Diagnostic logs
        try {
          const monitorClient = this.client.monitor();
          const settingsResult = await monitorClient.diagnosticSettings.list(ws.id!);
          const settings: any[] = settingsResult.value ?? [];
          const hasLogs = settings.some(s =>
            s.logs?.some((l: any) => l.enabled) || s.metrics?.some((m: any) => m.enabled),
          );
          if (!hasLogs) {
            findings.push(this.finding(
              'Azure ML workspace has no diagnostic logs configured',
              `Machine Learning workspace "${name}" has no diagnostic settings. Without logs, model training runs, job submissions, and data access cannot be audited.`,
              'MEDIUM',
              { workspace: name, resourceGroup: rg },
              'Enable diagnostic settings to capture AmlComputeClusterEvent, AmlRunStatusChangedEvent, and AmlDataLabelingWorkspaceUserLog categories to a Log Analytics workspace.',
              ['machinelearning', 'logging'],
            ));
          }
        } catch { /* optional */ }

        // 7. Compute clusters — check for public IP on compute
        try {
          const computes: any[] = [];
          for await (const c of amlClient.computeOperations.list(rg, name)) computes.push(c);

          for (const compute of computes) {
            const props = compute.properties as any;
            if (props?.enableNodePublicIp !== false &&
                (compute.computeType === 'AmlCompute' || compute.computeType === 'ComputeInstance')) {
              findings.push(this.finding(
                'Azure ML compute has public IP enabled on nodes',
                `ML compute "${compute.name}" in workspace "${name}" has public IP enabled on compute nodes. Public IPs on compute nodes increase attack surface and may expose training infrastructure to the internet.`,
                'MEDIUM',
                { workspace: name, compute: compute.name, resourceGroup: rg, computeType: compute.computeType },
                'Set enableNodePublicIp to false on the compute cluster/instance and ensure access is routed through the private VNet.',
                ['machinelearning', 'compute', 'network'],
              ));
            }

            // Compute Instance — check SSH access
            if (compute.computeType === 'ComputeInstance') {
              const sshAccess = props?.sshSettings?.sshPublicAccess ?? 'Enabled';
              if (sshAccess === 'Enabled') {
                findings.push(this.finding(
                  'Azure ML Compute Instance has SSH public access enabled',
                  `ML Compute Instance "${compute.name}" in workspace "${name}" has public SSH access enabled. Direct SSH access to compute nodes bypasses workspace-level controls.`,
                  'HIGH',
                  { workspace: name, compute: compute.name, resourceGroup: rg },
                  'Disable SSH public access on the Compute Instance. Use Azure ML Studio terminal or Azure Bastion for interactive access.',
                  ['machinelearning', 'compute', 'ssh'],
                ));
              }
            }
          }
        } catch { /* optional */ }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Machine Learning scan error',
        `Could not complete ML workspace scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Machine Learning workspace resources.',
      ));
    }

    return findings;
  }
}
