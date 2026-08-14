// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const databricksChecks: CheckMetadata[] = [
  {
    checkId: 'databricks_workspace_cmk_encryption_enabled',
    provider: 'azure',
    service: 'databricks',
    title: 'Databricks Workspace Uses Customer-Managed Key Encryption',
    severity: 'HIGH',
    description: 'Checks that Azure Databricks workspaces use a customer-managed key (CMK) for managed-disk encryption at rest, instead of relying solely on provider-controlled keys.',
    remediation: 'Enable customer-managed key encryption on the workspace via Key Vault (Settings > Encryption), set the key source to Microsoft Key Vault, and select a Key Vault key and version for managed disks.',
    tags: ['databricks', 'encryption', 'cmk'],
  },
  {
    checkId: 'databricks_workspace_no_public_ip_enabled',
    provider: 'azure',
    service: 'databricks',
    title: 'Databricks Workspace Has Secure Cluster Connectivity Enabled',
    severity: 'MEDIUM',
    description: 'Checks that Azure Databricks workspaces are deployed with secure cluster connectivity (No Public IP), so classic-compute cluster nodes are not assigned public IP addresses. Serverless workspaces do not expose this setting and are flagged for manual verification.',
    remediation: 'Secure cluster connectivity can only be set at workspace creation. Deploy new workspaces with No Public IP enabled, migrate workloads, and decommission workspaces that expose cluster nodes publicly.',
    tags: ['databricks', 'network', 'public-access'],
  },
  {
    checkId: 'databricks_workspace_public_network_access_disabled',
    provider: 'azure',
    service: 'databricks',
    title: 'Databricks Workspace Has Public Network Access Disabled',
    severity: 'HIGH',
    description: 'Checks that Azure Databricks workspaces restrict connectivity to private endpoints by disabling public network access to the control plane and data plane.',
    remediation: 'In the workspace Networking settings, set Public network access to Disabled and configure Azure Private Link private endpoints so clients retain connectivity before enforcing the change.',
    tags: ['databricks', 'network', 'public-access'],
  },
  {
    checkId: 'databricks_workspace_vnet_injection_enabled',
    provider: 'azure',
    service: 'databricks',
    title: 'Databricks Workspace Is Deployed In A Customer-Managed VNet',
    severity: 'HIGH',
    description: 'Checks that Azure Databricks workspaces use VNet injection, meaning they are deployed into a customer-managed virtual network rather than a Databricks-managed network, giving control over routing, egress, and access boundaries.',
    remediation: 'Deploy the workspace with VNet injection by attaching a customer-managed VNet with dedicated host (public) and container (private) subnets, then apply least-privilege NSG rules and egress controls.',
    tags: ['databricks', 'network', 'vnet'],
  },
];
