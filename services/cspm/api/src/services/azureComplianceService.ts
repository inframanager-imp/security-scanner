/**
 * Azure Compliance Scoring Engine
 *
 * Frameworks: CIS Azure Foundations Benchmark, NIST SP 800-53, ISO 27001, SOC 2, HIPAA
 *
 * A control PASSES when zero OPEN/ACKNOWLEDGED Azure findings map to it.
 * Score = passing / (passing + failing) * 100  (NOT_EVALUATED excluded from denominator).
 */

export type AzureFrameworkId = 'CIS_AZURE' | 'NIST' | 'ISO27001' | 'SOC2' | 'HIPAA';

export interface AzureComplianceControl {
  id: string;
  name: string;
  description: string;
  /** Finding titles from Azure scanners that indicate this control is violated */
  findingTitles: string[];
}

export interface AzureComplianceFramework {
  id: AzureFrameworkId;
  name: string;
  shortName: string;
  controls: AzureComplianceControl[];
}

export interface AzureControlResult extends AzureComplianceControl {
  status: 'PASS' | 'FAIL' | 'NOT_EVALUATED';
  failingFindings: number;
}

export interface AzureFrameworkScore {
  frameworkId: AzureFrameworkId;
  frameworkName: string;
  shortName: string;
  score: number;
  passingControls: number;
  failingControls: number;
  notEvaluatedControls: number;
  totalControls: number;
  controls: AzureControlResult[];
}

// ---------------------------------------------------------------------------
// Shared finding title groups
// ---------------------------------------------------------------------------

const IAM_FINDINGS = [
  'Excessive subscription-level Owner/Contributor assignments',
  'Service principals with subscription Owner role',
  'Orphaned role assignments — principal no longer exists',
  'High number of privileged role assignments',
  'Classic co-administrator accounts detected',
  'Guest users assigned privileged Azure roles',
  'Custom role definitions with wildcard (*) permissions',
  'Managed identities with subscription-level Owner or Contributor',
];

const ENTRA_FINDINGS = [
  'No Conditional Access policy enforcing MFA for all users',
  'No Conditional Access policy blocking legacy authentication',
  'No Conditional Access policies configured',
  'All Conditional Access policies are in report-only mode',
  'Excessive Global Administrator assignments',
  'No Global Administrator accounts found',
  'Guest (external) users assigned privileged directory roles',
  'Stale guest users with no sign-in in 90 days',
  'Service principals with credentials expiring within 30 days',
  'Service principals with expired credentials',
  'Multi-tenant service principals detected',
];

const ACR_FINDINGS = [
  'ACR admin user account is enabled',
  'Container registry is publicly accessible from all networks',
  'ACR content trust (image signing) is not enabled',
  'ACR quarantine policy is not enabled',
  'Container registry is using the Basic SKU',
];

const AKS_CONTAINER_FINDINGS = [
  'AKS cluster has Kubernetes RBAC disabled',
  'AKS cluster not integrated with Azure Active Directory',
  'AKS cluster allows local Kubernetes accounts',
  'AKS cluster has no Kubernetes network policy configured',
  'AKS cluster API server is publicly accessible',
  'AKS cluster API server has no authorized IP ranges configured',
  'AKS cluster Azure Policy add-on is not enabled',
  'AKS cluster workload identity (OIDC) is not enabled',
  'AKS cluster has HTTP application routing add-on enabled',
  'AKS cluster is running an end-of-life Kubernetes version',
];

const STORAGE_FINDINGS = [
  'Storage account allows public blob access',
  'Storage account allows HTTP traffic',
  'Storage account uses weak minimum TLS version',
  'Storage account network access not restricted',
  'Storage account has no private endpoint configured',
  'Storage account allows shared key (account key) access',
  'Storage account blob soft delete not enabled',
  'Storage account lacks infrastructure encryption',
  'Storage account not using customer-managed keys',
];

const VM_FINDINGS = [
  'Virtual machine OS disk not encrypted',
  'Virtual Machine Scale Set OS disk not encrypted',
  'Virtual machine has public IP with management ports exposed',
  'Virtual machine has a public IP address',
  'Virtual machine does not use managed identity',
  'Virtual machine running end-of-life operating system',
  'Virtual Machine Scale Set running end-of-life operating system',
  'Virtual Machine Scale Set does not use managed identity',
];

const SQL_FINDINGS = [
  'SQL Server has public network access enabled',
  'SQL Server firewall allows access from all IP addresses',
  'SQL Server has no Azure AD administrator configured',
  'SQL Server auditing is disabled',
  'SQL Database Transparent Data Encryption (TDE) disabled',
  'SQL Database threat detection (Advanced Threat Protection) disabled',
];

const KEYVAULT_FINDINGS = [
  'Key Vault soft delete is disabled',
  'Key Vault purge protection is disabled',
  'Key Vault is publicly accessible from all networks',
  'Key Vault uses legacy access policies instead of Azure RBAC',
];

const NSG_FINDINGS = [
  'NSG rule allows unrestricted inbound traffic from internet',
  'NSG rule exposes sensitive port(s) to the internet',
  'Network Security Group is not associated with any subnet or NIC',
];

const NETWORK_FINDINGS = [
  'No Azure Firewall deployed in subscription',
  'Azure Firewall is deployed but appears to be deallocated',
  'Route table sends default traffic directly to Internet',
  'Subnets without a Network Security Group',
  'VNets without DDoS Protection Plan',
];

const APPSERVICE_FINDINGS = [
  'App Service allows HTTP traffic',
  'App Service uses weak minimum TLS version',
  'App Service allows unencrypted FTP access',
  'App Service remote debugging is enabled',
  'App Service does not use managed identity',
];

const COSMOS_FINDINGS = [
  'CosmosDB account has public network access enabled',
  'CosmosDB account has no IP or VNet firewall rules',
  'CosmosDB account allows key-based (local) authentication',
  'CosmosDB account allows all Azure services to bypass firewall',
];

const REDIS_FINDINGS = [
  'Redis Cache has non-SSL port (6379) enabled',
  'Redis Cache allows connections below TLS 1.2',
  'Redis Cache has public network access enabled',
  'Redis Cache is using the Basic SKU',
  'Redis Cache firewall allows access from all IP addresses',
  'Redis Cache has no firewall rules configured',
  'Redis Cache is running an end-of-life Redis version',
  'Redis Cache uses access key authentication instead of Microsoft Entra ID',
];

const SERVICEBUS_FINDINGS = [
  'Service Bus namespace has public network access enabled',
  'Service Bus namespace allows connections below TLS 1.2',
  'Service Bus namespace uses SAS key authentication instead of Microsoft Entra ID',
  'Service Bus namespace has no private endpoint configured',
  'Service Bus namespace has no diagnostic logs configured',
];

const EVENTHUB_FINDINGS = [
  'Event Hub namespace has public network access enabled',
  'Event Hub namespace allows connections below TLS 1.2',
  'Event Hub namespace uses SAS key authentication instead of Microsoft Entra ID',
  'Event Hub namespace has no private endpoint configured',
  'Event Hub namespace has no diagnostic logs configured',
];

const POSTGRES_FINDINGS = [
  'PostgreSQL Flexible Server has public network access enabled',
  'PostgreSQL Flexible Server does not require SSL connections',
  'PostgreSQL Flexible Server firewall allows access from all IP addresses',
  'PostgreSQL Flexible Server has an overly permissive firewall rule',
  'PostgreSQL Flexible Server has insufficient backup retention period',
  'PostgreSQL Flexible Server has geo-redundant backup disabled',
  'PostgreSQL Flexible Server has High Availability disabled',
  'PostgreSQL Flexible Server does not use Microsoft Entra ID authentication',
  'PostgreSQL Flexible Server runs an end-of-life PostgreSQL version',
];

const MYSQL_FINDINGS = [
  'MySQL Flexible Server has public network access enabled',
  'MySQL Flexible Server does not require SSL connections',
  'MySQL Flexible Server firewall allows access from all IP addresses',
  'MySQL Flexible Server has an overly permissive firewall rule',
  'MySQL Flexible Server has insufficient backup retention period',
  'MySQL Flexible Server has geo-redundant backup disabled',
  'MySQL Flexible Server has High Availability disabled',
  'MySQL Flexible Server has no Microsoft Entra ID administrator configured',
  'MySQL Flexible Server audit logging is not enabled',
  'MySQL Flexible Server runs an end-of-life MySQL version',
];

const COGNITIVE_FINDINGS = [
  'Cognitive Services / AI account has public network access enabled',
  'Cognitive Services / AI account has no network access restrictions',
  'Cognitive Services / AI account has no managed identity assigned',
  'Cognitive Services / AI account does not use a customer-managed encryption key',
  'Cognitive Services / AI account has no diagnostic logs configured',
  'Azure OpenAI deployment has content filtering disabled',
  'Azure AI Foundry account does not restrict outbound network access',
];

const APIM_FINDINGS = [
  'API Management gateway exposes an HTTP (non-HTTPS) endpoint',
  'API Management gateway allows deprecated TLS/SSL protocols',
  'API Management service has no Virtual Network integration',
  'API Management service gateway is publicly accessible',
  'API Management service has no WAF or Azure Front Door in front',
  'API Management has backends with SSL certificate validation disabled',
  'API Management has named values with potential plaintext secrets',
  'API Management service has no managed identity assigned',
  'API Management service has no diagnostic logs configured',
];

const FUNCTIONS_FINDINGS = [
  'Azure Function App does not enforce HTTPS',
  'Azure Function App allows connections below TLS 1.2',
  'Azure Function App has HTTP triggers with anonymous authentication',
  'Azure Function App has no managed identity assigned',
  'Azure Function App has CORS configured to allow all origins (*)',
  'Azure Function App uses an end-of-life runtime version',
  'Azure Function App has remote debugging enabled',
];

const CONTAINER_APPS_FINDINGS = [
  'Container Apps Environment has no Virtual Network integration',
  'Container Apps Environment is configured with external (public) access',
  'Azure Container App has external HTTP ingress without TLS',
  'Azure Container App allows insecure HTTP connections',
  'Azure Container App has no managed identity assigned',
  'Azure Container App has potential secrets in plaintext environment variables',
  'Azure Container App runs a privileged container',
];

const APP_GATEWAY_FINDINGS = [
  'Application Gateway is not using the WAF SKU',
  'Application Gateway WAF is disabled',
  'Application Gateway WAF is in Detection mode, not Prevention mode',
  'Application Gateway has HTTP listeners without HTTPS redirect',
  'Application Gateway allows deprecated TLS versions',
  'Application Gateway communicates with backends over HTTP (not HTTPS)',
  'Application Gateway has no managed identity assigned',
  'Application Gateway WAF uses an outdated OWASP CRS rule set',
];

const AML_FINDINGS = [
  'Azure ML workspace has public network access enabled',
  'Azure ML workspace has no managed network isolation',
  'Azure ML workspace does not use a customer-managed encryption key',
  'Azure ML workspace has no managed identity assigned',
  'Azure ML Compute Instance has SSH public access enabled',
  'Azure ML compute has public IP enabled on nodes',
];

const ADF_FINDINGS = [
  'Azure Data Factory has public network access enabled',
  'Azure Data Factory has no managed virtual network configured',
  'Azure Data Factory has no managed identity assigned',
  'Azure Data Factory does not use a customer-managed encryption key',
  'Azure Data Factory Self-Hosted Integration Runtime has offline/expired nodes',
];

const SYNAPSE_FINDINGS = [
  'Azure Synapse workspace has public network access enabled',
  'Azure Synapse workspace does not use a managed virtual network',
  'Azure Synapse workspace allows SQL authentication (not Entra ID only)',
  'Azure Synapse workspace does not use a customer-managed key for encryption',
  'Synapse SQL Pool has Transparent Data Encryption (TDE) disabled',
  'Synapse SQL Pool auditing is disabled',
  'Azure Synapse workspace firewall allows access from all IP addresses',
];

const BACKUP_FINDINGS = [
  'Azure Backup vault has soft delete disabled',
  'Azure Backup vault does not have Multi-User Authorization (MUA) enabled',
  'Azure Backup vault does not have immutability enabled',
  'Azure Backup vault has Cross Region Restore (CRR) disabled',
  'Azure Backup vault does not use a customer-managed key for encryption',
  'Azure Backup vault has public network access enabled',
];

const LOG_ANALYTICS_FINDINGS = [
  'No Log Analytics workspace found in subscription',
  'Log Analytics workspace has insufficient data retention period',
  'Log Analytics workspace allows public network access for ingestion or query',
  'Log Analytics workspace does not use a customer-managed key',
  'Log Analytics workspace has no data export rules configured',
  'Log Analytics workspace allows workspace-level access (not resource-context mode)',
];

const EVENT_GRID_FINDINGS = [
  'Event Grid topic has public network access enabled',
  'Event Grid topic uses SAS key authentication instead of Microsoft Entra ID',
  'Event Grid domain has public network access enabled',
  'Event Grid domain uses SAS key authentication instead of Microsoft Entra ID',
  'Event Grid topic allows connections below TLS 1.2',
  'Event Grid event subscription delivers events to an HTTP (non-HTTPS) endpoint',
];

const IOT_HUB_FINDINGS = [
  'Azure IoT Hub allows device connections below TLS 1.2',
  'Azure IoT Hub has public network access enabled',
  'Azure IoT Hub has no IP filtering configured',
  'Azure IoT Hub has a shared access policy with excessive permissions',
  'Azure IoT Hub has no private endpoint configured',
];

const SEARCH_FINDINGS = [
  'Azure AI Search service has public network access enabled',
  'Azure AI Search service uses API key authentication instead of Microsoft Entra ID',
  'Azure AI Search service has no private endpoint configured',
  'Azure AI Search service does not enforce customer-managed key encryption',
  'Azure AI Search service has no managed identity assigned',
  'Azure AI Search service has no IP firewall rules configured',
];

const AUTOMATION_FINDINGS = [
  'Azure Automation account has public network access enabled',
  'Azure Automation account does not use managed identity (Run As account risk)',
  'Azure Automation account does not use a customer-managed encryption key',
  'Azure Automation account has unencrypted variables with sensitive names',
];

const THREAT_FINDINGS = [
  'Suspicious mass read of secrets from Key Vault',
  'Suspicious privilege escalation: new Owner assignment',
  'Impossible travel: sign-in from two distant locations',
  'Brute force: multiple failed sign-ins followed by success',
  'Anomalous deletion of resources',
  'Suspicious API calls from anonymous/unknown principal',
  'NSG rule modified to open management port to internet',
  'Large-scale data export from Storage account',
  'Privileged role assigned outside change window',
];

// ---------------------------------------------------------------------------
// Framework Definitions
// ---------------------------------------------------------------------------

export const AZURE_FRAMEWORKS: AzureComplianceFramework[] = [

  // ──────────────────────────────────────────────────────────────────────────
  // CIS Microsoft Azure Foundations Benchmark v2.0
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: 'CIS_AZURE',
    name: 'CIS Microsoft Azure Foundations Benchmark v2.0',
    shortName: 'CIS Azure',
    controls: [
      {
        id: 'CIS-1.1',
        name: 'IAM — Subscription Owners',
        description: 'Ensure there are no more than 3 subscriptions owners assigned.',
        findingTitles: ['Subscription has too many Owners or Contributors'],
      },
      {
        id: 'CIS-1.2',
        name: 'IAM — Privileged Roles',
        description: 'Ensure Owner/Contributor is not assigned broadly at subscription scope.',
        findingTitles: ['Privileged role assigned at subscription scope'],
      },
      {
        id: 'CIS-1.3',
        name: 'IAM — Custom Roles',
        description: 'Ensure no custom roles have wildcard (*) permissions.',
        findingTitles: ['Custom role with wildcard action (*) permission'],
      },
      {
        id: 'CIS-2.1',
        name: 'Storage — Public Blob Access',
        description: 'Ensure that Storage Account public blob access is disallowed.',
        findingTitles: [
          'Storage account allows public blob access',
          'Storage account network access not restricted',
        ],
      },
      {
        id: 'CIS-2.2',
        name: 'Storage — HTTPS & TLS',
        description: 'Ensure that Storage Account requires HTTPS and TLS 1.2+.',
        findingTitles: [
          'Storage account allows HTTP traffic',
          'Storage account uses weak minimum TLS version',
        ],
      },
      {
        id: 'CIS-2.3',
        name: 'Storage — Shared Key Access',
        description: 'Ensure that Storage Account access keys are not used for access.',
        findingTitles: ['Storage account allows shared key (account key) access'],
      },
      {
        id: 'CIS-3.1',
        name: 'SQL — Firewall',
        description: 'Ensure that SQL Server firewall does not allow 0.0.0.0–255.255.255.255.',
        findingTitles: [
          'SQL Server has public network access enabled',
          'SQL Server firewall allows access from all IP addresses',
        ],
      },
      {
        id: 'CIS-3.2',
        name: 'SQL — Azure AD Admin',
        description: 'Ensure that an Azure Active Directory administrator is configured for SQL Server.',
        findingTitles: ['SQL Server has no Azure AD administrator configured'],
      },
      {
        id: 'CIS-3.3',
        name: 'SQL — Auditing',
        description: 'Ensure that auditing is enabled for SQL Server.',
        findingTitles: ['SQL Server auditing is disabled'],
      },
      {
        id: 'CIS-3.4',
        name: 'SQL — TDE',
        description: 'Ensure that Transparent Data Encryption is enabled for SQL databases.',
        findingTitles: ['SQL Database Transparent Data Encryption (TDE) disabled'],
      },
      {
        id: 'CIS-4.1',
        name: 'Key Vault — Soft Delete',
        description: 'Ensure that soft delete is enabled for Azure Key Vault.',
        findingTitles: ['Key Vault soft delete is disabled'],
      },
      {
        id: 'CIS-4.2',
        name: 'Key Vault — Purge Protection',
        description: 'Ensure that purge protection is enabled for Azure Key Vault.',
        findingTitles: ['Key Vault purge protection is disabled'],
      },
      {
        id: 'CIS-4.3',
        name: 'Key Vault — Network Access',
        description: 'Ensure that Azure Key Vault disables public network access.',
        findingTitles: ['Key Vault is publicly accessible from all networks'],
      },
      {
        id: 'CIS-4.4',
        name: 'Key Vault — RBAC',
        description: 'Ensure Key Vault uses Azure RBAC permission model.',
        findingTitles: ['Key Vault uses legacy access policies instead of Azure RBAC'],
      },
      {
        id: 'CIS-5.1',
        name: 'NSG — Inbound Rules',
        description: 'Ensure that no NSG rule allows unrestricted inbound access on sensitive ports.',
        findingTitles: [
          'NSG rule allows unrestricted inbound traffic from internet',
          'NSG rule exposes sensitive port(s) to the internet',
          'Subnets without a Network Security Group',
        ],
      },
      {
        id: 'CIS-6.1',
        name: 'VM — Disk Encryption',
        description: 'Ensure that disk encryption is applied to VMs.',
        findingTitles: [
          'Virtual machine OS disk not encrypted',
          'Virtual Machine Scale Set OS disk not encrypted',
        ],
      },
      {
        id: 'CIS-6.2',
        name: 'VM — Managed Identity',
        description: 'Ensure VMs authenticate via managed identity instead of stored credentials.',
        findingTitles: [
          'Virtual machine does not use managed identity',
          'Virtual Machine Scale Set does not use managed identity',
        ],
      },
      {
        id: 'CIS-7.1',
        name: 'App Service — HTTPS',
        description: 'Ensure App Service enforces HTTPS-only and TLS 1.2+.',
        findingTitles: [
          'App Service allows HTTP traffic',
          'App Service uses weak minimum TLS version',
          'App Service allows unencrypted FTP access',
        ],
      },
      {
        id: 'CIS-7.2',
        name: 'App Service — Managed Identity',
        description: 'Ensure App Service uses managed identity for resource access.',
        findingTitles: ['App Service does not use managed identity'],
      },
      {
        id: 'CIS-8.1',
        name: 'Threat Detection',
        description: 'Ensure anomalous activity and threats are actively monitored.',
        findingTitles: THREAT_FINDINGS,
      },
      {
        id: 'CIS-9.1',
        name: 'Entra ID — MFA & Conditional Access',
        description: 'Ensure MFA is enforced and legacy authentication is blocked via Conditional Access.',
        findingTitles: [
          'No Conditional Access policy enforcing MFA for all users',
          'No Conditional Access policy blocking legacy authentication',
          'No Conditional Access policies configured',
          'All Conditional Access policies are in report-only mode',
        ],
      },
      {
        id: 'CIS-9.2',
        name: 'Entra ID — Privileged Roles',
        description: 'Ensure privileged directory roles are not over-assigned and PIM is used.',
        findingTitles: [
          'Excessive Global Administrator assignments',
          'Guest (external) users assigned privileged directory roles',
          ...ENTRA_FINDINGS.filter(f => f.includes('privileged') || f.includes('Administrator')),
        ],
      },
      {
        id: 'CIS-9.3',
        name: 'Entra ID — Service Principal Hygiene',
        description: 'Ensure service principals have valid credentials and are not orphaned.',
        findingTitles: [
          'Service principals with credentials expiring within 30 days',
          'Service principals with expired credentials',
          'Multi-tenant service principals detected',
        ],
      },
      {
        id: 'CIS-10.1',
        name: 'Container Registry Security',
        description: 'Ensure container registries are configured securely.',
        findingTitles: ACR_FINDINGS,
      },
      {
        id: 'CIS-10.2',
        name: 'AKS Security',
        description: 'Ensure AKS clusters enforce RBAC, network policy, and policy controls.',
        findingTitles: AKS_CONTAINER_FINDINGS,
      },
      {
        id: 'CIS-1.4',
        name: 'IAM — Managed Identity Risks',
        description: 'Ensure managed identities follow least privilege.',
        findingTitles: [
          'Managed identities with subscription-level Owner or Contributor',
          'User-assigned managed identities with no role assignments',
        ],
      },
      {
        id: 'CIS-11.1',
        name: 'Redis Cache Security',
        description: 'Ensure Redis Cache uses TLS, disables non-SSL port, and restricts network access.',
        findingTitles: REDIS_FINDINGS,
      },
      {
        id: 'CIS-11.2',
        name: 'Service Bus Security',
        description: 'Ensure Service Bus uses Entra ID auth, TLS 1.2+, and restricts public access.',
        findingTitles: SERVICEBUS_FINDINGS,
      },
      {
        id: 'CIS-11.3',
        name: 'Event Hub Security',
        description: 'Ensure Event Hub uses Entra ID auth, TLS 1.2+, and restricts public access.',
        findingTitles: EVENTHUB_FINDINGS,
      },
      {
        id: 'CIS-12.1',
        name: 'PostgreSQL Flexible Server Security',
        description: 'Ensure PostgreSQL enforces SSL, restricts public access, and uses Entra ID auth.',
        findingTitles: POSTGRES_FINDINGS,
      },
      {
        id: 'CIS-12.2',
        name: 'MySQL Flexible Server Security',
        description: 'Ensure MySQL enforces SSL, restricts public access, and uses Entra ID auth.',
        findingTitles: MYSQL_FINDINGS,
      },
      {
        id: 'CIS-13.1',
        name: 'Cognitive Services / AI Security',
        description: 'Ensure AI services restrict public access, use managed identity, and enable CMK.',
        findingTitles: COGNITIVE_FINDINGS,
      },
      {
        id: 'CIS-13.2',
        name: 'API Management Security',
        description: 'Ensure APIM enforces HTTPS, TLS 1.2+, VNet integration, and WAF protection.',
        findingTitles: APIM_FINDINGS,
      },
      {
        id: 'CIS-14.1',
        name: 'Azure Functions Security',
        description: 'Ensure Function Apps enforce HTTPS, TLS 1.2+, and use managed identity.',
        findingTitles: FUNCTIONS_FINDINGS,
      },
      {
        id: 'CIS-14.2',
        name: 'Container Apps Security',
        description: 'Ensure Container Apps use VNet isolation, TLS, and managed identity.',
        findingTitles: CONTAINER_APPS_FINDINGS,
      },
      {
        id: 'CIS-14.3',
        name: 'Application Gateway WAF',
        description: 'Ensure Application Gateway uses WAF in Prevention mode with TLS 1.2+.',
        findingTitles: APP_GATEWAY_FINDINGS,
      },
      {
        id: 'CIS-15.1',
        name: 'Azure Machine Learning Security',
        description: 'Ensure ML workspaces restrict public access and use managed network isolation.',
        findingTitles: AML_FINDINGS,
      },
      {
        id: 'CIS-15.2',
        name: 'Azure Data Factory Security',
        description: 'Ensure ADF uses managed VNet, managed identity, and disables public access.',
        findingTitles: ADF_FINDINGS,
      },
      {
        id: 'CIS-15.3',
        name: 'Azure Synapse Analytics Security',
        description: 'Ensure Synapse workspaces use Entra ID auth, TDE, and restrict network access.',
        findingTitles: SYNAPSE_FINDINGS,
      },
      {
        id: 'CIS-16.1',
        name: 'Azure Backup Security',
        description: 'Ensure Recovery Services vaults use soft delete, immutability, and MUA.',
        findingTitles: BACKUP_FINDINGS,
      },
      {
        id: 'CIS-16.2',
        name: 'Azure Monitor / Log Analytics',
        description: 'Ensure Log Analytics workspaces have sufficient retention and restrict public access.',
        findingTitles: LOG_ANALYTICS_FINDINGS,
      },
      {
        id: 'CIS-17.1',
        name: 'IoT Hub Security',
        description: 'Ensure IoT Hubs enforce TLS 1.2, IP filtering, and least-privilege policies.',
        findingTitles: IOT_HUB_FINDINGS,
      },
      {
        id: 'CIS-17.2',
        name: 'Event Grid Security',
        description: 'Ensure Event Grid topics/domains restrict public access and use Entra ID auth.',
        findingTitles: EVENT_GRID_FINDINGS,
      },
      {
        id: 'CIS-17.3',
        name: 'AI Search Security',
        description: 'Ensure AI Search services restrict public access and use Entra ID auth.',
        findingTitles: SEARCH_FINDINGS,
      },
      {
        id: 'CIS-17.4',
        name: 'Azure Automation Security',
        description: 'Ensure Automation accounts use managed identity and restrict public access.',
        findingTitles: AUTOMATION_FINDINGS,
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // NIST SP 800-53 Rev 5 (mapped to Azure findings)
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: 'NIST',
    name: 'NIST SP 800-53 Rev 5',
    shortName: 'NIST 800-53',
    controls: [
      {
        id: 'NIST-AC-2',
        name: 'Account Management',
        description: 'Manage information system accounts including establishment and removal.',
        findingTitles: [
          ...IAM_FINDINGS,
          'Stale guest users with no sign-in in 90 days',
          'Service principals with expired credentials',
        ],
      },
      {
        id: 'NIST-AC-3',
        name: 'Access Enforcement',
        description: 'Enforce approved authorizations for logical access.',
        findingTitles: [
          ...IAM_FINDINGS,
          'Key Vault uses legacy access policies instead of Azure RBAC',
          'CosmosDB account allows key-based (local) authentication',
          'SQL Server has no Azure AD administrator configured',
          'No Conditional Access policy enforcing MFA for all users',
          'No Conditional Access policy blocking legacy authentication',
        ],
      },
      {
        id: 'NIST-AC-17',
        name: 'Remote Access',
        description: 'Establish and document usage restrictions for remote access.',
        findingTitles: [
          'Virtual machine has public IP with management ports exposed',
          'NSG rule exposes sensitive port(s) to the internet',
          'App Service remote debugging is enabled',
        ],
      },
      {
        id: 'NIST-AU-2',
        name: 'Event Logging',
        description: 'Identify events to be logged by the information system.',
        findingTitles: [
          'SQL Server auditing is disabled',
          'Verify Key Vault diagnostic logging is enabled',
        ],
      },
      {
        id: 'NIST-AU-9',
        name: 'Protection of Audit Information',
        description: 'Protect audit information and tools from unauthorized modification.',
        findingTitles: [
          'Storage account blob soft delete not enabled',
          'Key Vault soft delete is disabled',
          'Key Vault purge protection is disabled',
        ],
      },
      {
        id: 'NIST-CA-7',
        name: 'Continuous Monitoring',
        description: 'Develop a continuous monitoring strategy for security controls.',
        findingTitles: THREAT_FINDINGS,
      },
      {
        id: 'NIST-CM-7',
        name: 'Least Functionality',
        description: 'Configure the system to provide only essential capabilities.',
        findingTitles: [
          'App Service allows unencrypted FTP access',
          'App Service remote debugging is enabled',
          'Virtual machine running end-of-life operating system',
          'Virtual Machine Scale Set running end-of-life operating system',
        ],
      },
      {
        id: 'NIST-IA-5',
        name: 'Authenticator Management',
        description: 'Manage information system authenticators including passwords and keys.',
        findingTitles: [
          'Storage account allows shared key (account key) access',
          'CosmosDB account allows key-based (local) authentication',
          'SQL Server has no Azure AD administrator configured',
        ],
      },
      {
        id: 'NIST-SC-5',
        name: 'Denial of Service Protection',
        description: 'Protect the system from denial of service attacks.',
        findingTitles: ['VNets without DDoS Protection Plan'],
      },
      {
        id: 'NIST-SC-7',
        name: 'Boundary Protection',
        description: 'Monitor and control communications at external boundaries.',
        findingTitles: [
          ...NSG_FINDINGS,
          ...NETWORK_FINDINGS,
          'SQL Server has public network access enabled',
          'CosmosDB account has public network access enabled',
          'Key Vault is publicly accessible from all networks',
          'Storage account network access not restricted',
        ],
      },
      {
        id: 'NIST-SC-8',
        name: 'Transmission Confidentiality and Integrity',
        description: 'Implement cryptographic mechanisms to prevent unauthorised disclosure during transmission.',
        findingTitles: [
          'Storage account allows HTTP traffic',
          'Storage account uses weak minimum TLS version',
          'App Service allows HTTP traffic',
          'App Service uses weak minimum TLS version',
          'App Service allows unencrypted FTP access',
        ],
      },
      {
        id: 'NIST-SC-28',
        name: 'Protection of Information at Rest',
        description: 'Implement cryptographic mechanisms to prevent unauthorised disclosure of stored information.',
        findingTitles: [
          'Virtual machine OS disk not encrypted',
          'Virtual Machine Scale Set OS disk not encrypted',
          'SQL Database Transparent Data Encryption (TDE) disabled',
          'Storage account lacks infrastructure encryption',
          'Storage account not using customer-managed keys',
        ],
      },
      {
        id: 'NIST-SI-2',
        name: 'Flaw Remediation',
        description: 'Identify, report, and correct information system flaws.',
        findingTitles: [
          'Virtual machine running end-of-life operating system',
          'Virtual Machine Scale Set running end-of-life operating system',
        ],
      },
      {
        id: 'NIST-SI-3',
        name: 'Malicious Code Protection',
        description: 'Implement controls to protect against malicious code.',
        findingTitles: THREAT_FINDINGS,
      },
      {
        id: 'NIST-IA-2',
        name: 'Identification and Authentication — Organisational Users',
        description: 'Uniquely identify and authenticate organisational users including MFA.',
        findingTitles: [
          'No Conditional Access policy enforcing MFA for all users',
          'No Conditional Access policies configured',
          'Excessive Global Administrator assignments',
        ],
      },
      {
        id: 'NIST-SA-10',
        name: 'Developer Configuration Management',
        description: 'Require developers to manage and control changes to the system under development.',
        findingTitles: [
          ...ACR_FINDINGS,
          ...AKS_CONTAINER_FINDINGS,
        ],
      },
      {
        id: 'NIST-SC-8-EXT',
        name: 'Transmission Confidentiality — Messaging & APIs',
        description: 'Ensure messaging and API services encrypt data in transit using strong TLS.',
        findingTitles: [
          'Redis Cache has non-SSL port (6379) enabled',
          'Redis Cache allows connections below TLS 1.2',
          'Service Bus namespace allows connections below TLS 1.2',
          'Event Hub namespace allows connections below TLS 1.2',
          'PostgreSQL Flexible Server does not require SSL connections',
          'MySQL Flexible Server does not require SSL connections',
          'API Management gateway exposes an HTTP (non-HTTPS) endpoint',
          'API Management gateway allows deprecated TLS/SSL protocols',
          'API Management has backends with SSL certificate validation disabled',
        ],
      },
      {
        id: 'NIST-SC-7-EXT',
        name: 'Boundary Protection — Data Services',
        description: 'Restrict access to data and messaging services via network controls.',
        findingTitles: [
          'Redis Cache has public network access enabled',
          'Redis Cache firewall allows access from all IP addresses',
          'Service Bus namespace has public network access enabled',
          'Event Hub namespace has public network access enabled',
          'PostgreSQL Flexible Server has public network access enabled',
          'PostgreSQL Flexible Server firewall allows access from all IP addresses',
          'MySQL Flexible Server has public network access enabled',
          'MySQL Flexible Server firewall allows access from all IP addresses',
          'Cognitive Services / AI account has public network access enabled',
          'API Management service gateway is publicly accessible',
        ],
      },
      {
        id: 'NIST-SC-28-EXT',
        name: 'Protection of Information at Rest — AI & Databases',
        description: 'Implement cryptographic protections for AI workloads and managed databases.',
        findingTitles: [
          'Cognitive Services / AI account does not use a customer-managed encryption key',
          'PostgreSQL Flexible Server has geo-redundant backup disabled',
          'MySQL Flexible Server has geo-redundant backup disabled',
        ],
      },
      {
        id: 'NIST-AU-2-EXT',
        name: 'Event Logging — All Services',
        description: 'Ensure all Azure services emit and retain audit-ready logs.',
        findingTitles: [
          'No Log Analytics workspace found in subscription',
          'Log Analytics workspace has insufficient data retention period',
          ...FUNCTIONS_FINDINGS.filter(f => f.includes('logs')),
          ...ADF_FINDINGS.filter(f => f.includes('logs')),
          ...SYNAPSE_FINDINGS.filter(f => f.includes('logs') || f.includes('auditing')),
          ...AUTOMATION_FINDINGS.filter(f => f.includes('logs')),
        ],
      },
      {
        id: 'NIST-CP-9',
        name: 'Information System Backup',
        description: 'Conduct backups of user-level, system-level, and security-related information.',
        findingTitles: BACKUP_FINDINGS,
      },
      {
        id: 'NIST-SC-7-EXT2',
        name: 'Boundary Protection — Compute & AI',
        description: 'Restrict access to compute, AI, and analytics services via network controls.',
        findingTitles: [
          ...AML_FINDINGS.filter(f => f.includes('public') || f.includes('network')),
          ...ADF_FINDINGS.filter(f => f.includes('public') || f.includes('network')),
          ...SYNAPSE_FINDINGS.filter(f => f.includes('public') || f.includes('network') || f.includes('firewall')),
          ...IOT_HUB_FINDINGS.filter(f => f.includes('public') || f.includes('network') || f.includes('filtering')),
          'Application Gateway is not using the WAF SKU',
          'Application Gateway WAF is in Detection mode, not Prevention mode',
          'Container Apps Environment has no Virtual Network integration',
        ],
      },
      {
        id: 'NIST-IA-5-EXT',
        name: 'Authenticator Management — Messaging & AI Services',
        description: 'Manage authenticators for messaging, database, and AI services.',
        findingTitles: [
          'Redis Cache uses access key authentication instead of Microsoft Entra ID',
          'Service Bus namespace uses SAS key authentication instead of Microsoft Entra ID',
          'Event Hub namespace uses SAS key authentication instead of Microsoft Entra ID',
          'PostgreSQL Flexible Server does not use Microsoft Entra ID authentication',
          'MySQL Flexible Server has no Microsoft Entra ID administrator configured',
          'API Management has named values with potential plaintext secrets',
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // ISO/IEC 27001:2022
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: 'ISO27001',
    name: 'ISO/IEC 27001:2022',
    shortName: 'ISO 27001',
    controls: [
      {
        id: 'ISO-5.15',
        name: 'Access Control',
        description: 'Rules to control physical and logical access to information assets.',
        findingTitles: [
          ...IAM_FINDINGS,
          'Key Vault uses legacy access policies instead of Azure RBAC',
          'CosmosDB account allows key-based (local) authentication',
          'No Conditional Access policy enforcing MFA for all users',
          'Excessive Global Administrator assignments',
        ],
      },
      {
        id: 'ISO-5.17',
        name: 'Authentication Information',
        description: 'Allocation and management of authentication information.',
        findingTitles: [
          'Storage account allows shared key (account key) access',
          'SQL Server has no Azure AD administrator configured',
          'App Service does not use managed identity',
          'Virtual machine does not use managed identity',
          'No Conditional Access policy blocking legacy authentication',
          'Service principals with expired credentials',
        ],
      },
      {
        id: 'ISO-6.8',
        name: 'Vulnerability Management',
        description: 'Obtain information about technical vulnerabilities and take actions to reduce exposure.',
        findingTitles: [
          'Virtual machine running end-of-life operating system',
          'Virtual Machine Scale Set running end-of-life operating system',
        ],
      },
      {
        id: 'ISO-7.4',
        name: 'Physical Security Monitoring',
        description: 'Premises should be continuously monitored for unauthorized physical access.',
        findingTitles: THREAT_FINDINGS,
      },
      {
        id: 'ISO-8.6',
        name: 'Capacity Management',
        description: 'Ensure capacity and availability of systems.',
        findingTitles: ['CosmosDB account does not have automatic failover enabled'],
      },
      {
        id: 'ISO-8.9',
        name: 'Configuration Management',
        description: 'Security configurations of hardware, software and services shall be established.',
        findingTitles: [
          'App Service remote debugging is enabled',
          'App Service allows unencrypted FTP access',
          'Azure Firewall using Basic SKU',
          'Route table sends default traffic directly to Internet',
        ],
      },
      {
        id: 'ISO-8.12',
        name: 'Data Leakage Prevention',
        description: 'Measures applied to systems, networks and other devices to prevent data exfiltration.',
        findingTitles: [
          'Storage account allows public blob access',
          'CosmosDB account has public network access enabled',
          ...THREAT_FINDINGS,
        ],
      },
      {
        id: 'ISO-8.15',
        name: 'Logging',
        description: 'Logs that record activities, exceptions and other relevant events shall be produced and stored.',
        findingTitles: [
          'SQL Server auditing is disabled',
          'Verify Key Vault diagnostic logging is enabled',
        ],
      },
      {
        id: 'ISO-8.16',
        name: 'Monitoring Activities',
        description: 'Networks, systems and applications shall be monitored for anomalous behaviour.',
        findingTitles: THREAT_FINDINGS,
      },
      {
        id: 'ISO-8.20',
        name: 'Networks Security',
        description: 'Networks and network devices shall be secured and managed.',
        findingTitles: [
          ...NSG_FINDINGS,
          ...NETWORK_FINDINGS,
        ],
      },
      {
        id: 'ISO-8.24',
        name: 'Use of Cryptography',
        description: 'Rules for effective use of cryptography to protect confidentiality and integrity.',
        findingTitles: [
          'Virtual machine OS disk not encrypted',
          'SQL Database Transparent Data Encryption (TDE) disabled',
          'Storage account allows HTTP traffic',
          'Storage account lacks infrastructure encryption',
          'Key Vault soft delete is disabled',
          'Key Vault purge protection is disabled',
        ],
      },
      {
        id: 'ISO-8.25',
        name: 'Secure Development Lifecycle',
        description: 'Rules for secure development of software and systems.',
        findingTitles: ['App Service remote debugging is enabled'],
      },
      {
        id: 'ISO-8.24-EXT',
        name: 'Use of Cryptography — Messaging & Databases',
        description: 'Ensure cryptography is applied to data in transit and at rest for all data services.',
        findingTitles: [
          'Redis Cache has non-SSL port (6379) enabled',
          'Redis Cache allows connections below TLS 1.2',
          'PostgreSQL Flexible Server does not require SSL connections',
          'MySQL Flexible Server does not require SSL connections',
          'Cognitive Services / AI account does not use a customer-managed encryption key',
          'API Management gateway exposes an HTTP (non-HTTPS) endpoint',
        ],
      },
      {
        id: 'ISO-8.20-EXT',
        name: 'Network Security — Managed Services',
        description: 'Ensure network controls restrict access to managed PaaS services.',
        findingTitles: [
          ...REDIS_FINDINGS.filter(f => f.includes('network') || f.includes('firewall') || f.includes('public')),
          ...POSTGRES_FINDINGS.filter(f => f.includes('network') || f.includes('firewall') || f.includes('public')),
          ...MYSQL_FINDINGS.filter(f => f.includes('network') || f.includes('firewall') || f.includes('public')),
          'Cognitive Services / AI account has no network access restrictions',
          'API Management service has no Virtual Network integration',
          'API Management service has no WAF or Azure Front Door in front',
        ],
      },
      {
        id: 'ISO-8.13',
        name: 'Information Backup',
        description: 'Backup copies of information and software shall be maintained and regularly tested.',
        findingTitles: BACKUP_FINDINGS,
      },
      {
        id: 'ISO-8.23',
        name: 'Web Filtering',
        description: 'Access to external websites shall be managed to reduce exposure to malicious content.',
        findingTitles: [
          'Application Gateway is not using the WAF SKU',
          'Application Gateway WAF is in Detection mode, not Prevention mode',
          'Application Gateway WAF uses an outdated OWASP CRS rule set',
          'API Management service has no WAF or Azure Front Door in front',
        ],
      },
      {
        id: 'ISO-8.15-EXT',
        name: 'Logging — All Managed Services',
        description: 'Ensure all data, messaging, and compute services produce audit-ready logs.',
        findingTitles: [
          'Service Bus namespace has no diagnostic logs configured',
          'Event Hub namespace has no diagnostic logs configured',
          'Cognitive Services / AI account has no diagnostic logs configured',
          'API Management service has no diagnostic logs configured',
          'MySQL Flexible Server audit logging is not enabled',
          'No Log Analytics workspace found in subscription',
          'Log Analytics workspace has insufficient data retention period',
          'Azure Data Factory has no diagnostic logs configured',
          'Azure Synapse workspace has no diagnostic logs configured',
          'Azure Automation account has no diagnostic logs configured',
          'Azure IoT Hub has no diagnostic logs configured',
          'Azure AI Search service has no diagnostic logs configured',
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // SOC 2 Type II (Trust Services Criteria)
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: 'SOC2',
    name: 'SOC 2 Type II',
    shortName: 'SOC 2',
    controls: [
      {
        id: 'SOC2-CC6.1',
        name: 'Logical Access Security',
        description: 'Logical access security measures restrict access to information assets.',
        findingTitles: [
          ...IAM_FINDINGS,
          'Key Vault uses legacy access policies instead of Azure RBAC',
          'CosmosDB account allows key-based (local) authentication',
          'SQL Server has no Azure AD administrator configured',
          'No Conditional Access policy enforcing MFA for all users',
          'No Conditional Access policy blocking legacy authentication',
          'Excessive Global Administrator assignments',
        ],
      },
      {
        id: 'SOC2-CC6.3',
        name: 'Remove Unauthorised Access',
        description: 'Entity removes access to protected information assets when appropriate.',
        findingTitles: IAM_FINDINGS,
      },
      {
        id: 'SOC2-CC6.6',
        name: 'Logical Access from External Sources',
        description: 'Logical access security measures restrict access from external sources.',
        findingTitles: [
          'SQL Server has public network access enabled',
          'CosmosDB account has public network access enabled',
          'Key Vault is publicly accessible from all networks',
          'Storage account network access not restricted',
          'NSG rule allows unrestricted inbound traffic from internet',
          'NSG rule exposes sensitive port(s) to the internet',
          'Virtual machine has public IP with management ports exposed',
        ],
      },
      {
        id: 'SOC2-CC6.7',
        name: 'Transmission & Disclosure Restriction',
        description: 'The entity restricts the transmission, movement and removal of information.',
        findingTitles: [
          'Storage account allows HTTP traffic',
          'App Service allows HTTP traffic',
          'Storage account allows public blob access',
        ],
      },
      {
        id: 'SOC2-CC6.8',
        name: 'Prevention of Unauthorised Software',
        description: 'Controls protect against introduction of unauthorized or malicious software.',
        findingTitles: THREAT_FINDINGS,
      },
      {
        id: 'SOC2-CC7.1',
        name: 'Detect & Monitor',
        description: 'Detect and monitor for security events.',
        findingTitles: THREAT_FINDINGS,
      },
      {
        id: 'SOC2-CC7.2',
        name: 'Anomalies Identified & Evaluated',
        description: 'The entity evaluates security events to determine if they are security incidents.',
        findingTitles: THREAT_FINDINGS,
      },
      {
        id: 'SOC2-CC8.1',
        name: 'Change Management',
        description: 'Entity authorises, designs, develops and implements changes to infrastructure.',
        findingTitles: [
          'Route table sends default traffic directly to Internet',
          'NSG rule modified to open management port to internet',
        ],
      },
      {
        id: 'SOC2-A1.1',
        name: 'Availability — Capacity',
        description: 'The entity maintains, monitors and evaluates current processing capacity.',
        findingTitles: ['CosmosDB account does not have automatic failover enabled'],
      },
      {
        id: 'SOC2-C1.1',
        name: 'Confidentiality — Identification',
        description: 'The entity identifies and maintains confidential information.',
        findingTitles: [
          ...STORAGE_FINDINGS,
          ...COSMOS_FINDINGS,
        ],
      },
      {
        id: 'SOC2-PI1.1',
        name: 'Processing Integrity',
        description: 'Processing is complete, valid, accurate, timely and authorised.',
        findingTitles: [
          'SQL Database Transparent Data Encryption (TDE) disabled',
          'Key Vault soft delete is disabled',
          'Key Vault purge protection is disabled',
        ],
      },
      {
        id: 'SOC2-CC6.6-EXT',
        name: 'Logical Access — Data Services',
        description: 'Restrict access to data services from external sources.',
        findingTitles: [
          'Redis Cache has public network access enabled',
          'Redis Cache firewall allows access from all IP addresses',
          'PostgreSQL Flexible Server has public network access enabled',
          'PostgreSQL Flexible Server firewall allows access from all IP addresses',
          'MySQL Flexible Server has public network access enabled',
          'MySQL Flexible Server firewall allows access from all IP addresses',
          'Cognitive Services / AI account has public network access enabled',
          'Cognitive Services / AI account has no network access restrictions',
        ],
      },
      {
        id: 'SOC2-CC6.1-EXT',
        name: 'Logical Access Security — Messaging & AI',
        description: 'Ensure access to messaging and AI services uses identity-based controls.',
        findingTitles: [
          'Redis Cache uses access key authentication instead of Microsoft Entra ID',
          'Service Bus namespace uses SAS key authentication instead of Microsoft Entra ID',
          'Event Hub namespace uses SAS key authentication instead of Microsoft Entra ID',
          'PostgreSQL Flexible Server does not use Microsoft Entra ID authentication',
          'MySQL Flexible Server has no Microsoft Entra ID administrator configured',
          'API Management has named values with potential plaintext secrets',
          'Cognitive Services / AI account has no managed identity assigned',
          'API Management service has no managed identity assigned',
        ],
      },
      {
        id: 'SOC2-C1.1-EXT',
        name: 'Confidentiality — AI & Messaging',
        description: 'Ensure confidential data in AI and messaging services is protected.',
        findingTitles: [
          ...COGNITIVE_FINDINGS,
          'Redis Cache has non-SSL port (6379) enabled',
          'Redis Cache allows connections below TLS 1.2',
          ...AML_FINDINGS,
          ...SEARCH_FINDINGS,
        ],
      },
      {
        id: 'SOC2-A1.2',
        name: 'Availability — Backup & Recovery',
        description: 'The entity authorizes, designs, develops and implements changes to meet availability commitments.',
        findingTitles: BACKUP_FINDINGS,
      },
      {
        id: 'SOC2-CC6.7-EXT',
        name: 'Transmission Restriction — Compute & Functions',
        description: 'Ensure compute services restrict data transmission to encrypted channels.',
        findingTitles: [
          ...FUNCTIONS_FINDINGS.filter(f => f.includes('HTTPS') || f.includes('TLS')),
          ...CONTAINER_APPS_FINDINGS.filter(f => f.includes('HTTP') || f.includes('TLS')),
          ...APP_GATEWAY_FINDINGS.filter(f => f.includes('HTTP') || f.includes('TLS')),
          ...IOT_HUB_FINDINGS.filter(f => f.includes('TLS')),
          ...EVENT_GRID_FINDINGS.filter(f => f.includes('TLS') || f.includes('HTTP')),
        ],
      },
    ],
  },

  // ──────────────────────────────────────────────────────────────────────────
  // HIPAA Security Rule (mapped to Azure)
  // ──────────────────────────────────────────────────────────────────────────
  {
    id: 'HIPAA',
    name: 'HIPAA Security Rule',
    shortName: 'HIPAA',
    controls: [
      {
        id: 'HIPAA-164.308(a)(1)',
        name: 'Risk Analysis',
        description: 'Conduct an accurate assessment of potential risks to ePHI.',
        findingTitles: THREAT_FINDINGS,
      },
      {
        id: 'HIPAA-164.308(a)(3)',
        name: 'Workforce Access Management',
        description: 'Implement procedures for authorizing access to ePHI.',
        findingTitles: [
          ...IAM_FINDINGS,
          'No Conditional Access policy enforcing MFA for all users',
          'Excessive Global Administrator assignments',
        ],
      },
      {
        id: 'HIPAA-164.308(a)(5)',
        name: 'Security Awareness',
        description: 'Implement procedures for monitoring log-in attempts.',
        findingTitles: [
          'Brute force: multiple failed sign-ins followed by success',
          'Suspicious API calls from anonymous/unknown principal',
          'Suspicious privilege escalation: new Owner assignment',
          'No Conditional Access policy blocking legacy authentication',
        ],
      },
      {
        id: 'HIPAA-164.310(a)(2)',
        name: 'Facility Access Controls',
        description: 'Implement physical safeguards to limit access to ePHI.',
        findingTitles: [
          ...NSG_FINDINGS,
          'Virtual machine has public IP with management ports exposed',
        ],
      },
      {
        id: 'HIPAA-164.312(a)(1)',
        name: 'Access Control',
        description: 'Implement technical policies to allow access only to authorised persons.',
        findingTitles: [
          ...IAM_FINDINGS,
          'Key Vault uses legacy access policies instead of Azure RBAC',
          'SQL Server has no Azure AD administrator configured',
        ],
      },
      {
        id: 'HIPAA-164.312(a)(2)(ii)',
        name: 'Emergency Access Procedure',
        description: 'Establish procedures for obtaining necessary ePHI during an emergency.',
        findingTitles: ['CosmosDB account does not have automatic failover enabled'],
      },
      {
        id: 'HIPAA-164.312(b)',
        name: 'Audit Controls',
        description: 'Implement hardware, software and procedures to record and examine activity.',
        findingTitles: [
          'SQL Server auditing is disabled',
          'Verify Key Vault diagnostic logging is enabled',
        ],
      },
      {
        id: 'HIPAA-164.312(c)(1)',
        name: 'Integrity',
        description: 'Implement policies to protect ePHI from improper alteration or destruction.',
        findingTitles: [
          'Storage account blob soft delete not enabled',
          'Key Vault soft delete is disabled',
          'Key Vault purge protection is disabled',
          'CosmosDB account backup interval exceeds 24 hours',
          'CosmosDB account backup retention is less than 7 days',
        ],
      },
      {
        id: 'HIPAA-164.312(e)(1)',
        name: 'Transmission Security',
        description: 'Implement technical security measures to guard against unauthorized access during transmission.',
        findingTitles: [
          'Storage account allows HTTP traffic',
          'Storage account uses weak minimum TLS version',
          'App Service allows HTTP traffic',
          'App Service uses weak minimum TLS version',
          'App Service allows unencrypted FTP access',
        ],
      },
      {
        id: 'HIPAA-164.312(e)(2)(ii)',
        name: 'Encryption & Decryption of ePHI',
        description: 'Implement a mechanism to encrypt and decrypt ePHI.',
        findingTitles: [
          'Virtual machine OS disk not encrypted',
          'SQL Database Transparent Data Encryption (TDE) disabled',
          'Storage account lacks infrastructure encryption',
          'Storage account not using customer-managed keys',
          'CosmosDB account allows key-based (local) authentication',
          'Redis Cache has non-SSL port (6379) enabled',
          'Redis Cache allows connections below TLS 1.2',
          'PostgreSQL Flexible Server does not require SSL connections',
          'MySQL Flexible Server does not require SSL connections',
          'Cognitive Services / AI account does not use a customer-managed encryption key',
          'API Management gateway exposes an HTTP (non-HTTPS) endpoint',
          'API Management has backends with SSL certificate validation disabled',
        ],
      },
      {
        id: 'HIPAA-164.312(a)(1)-EXT',
        name: 'Access Control — Databases & AI',
        description: 'Restrict access to ePHI in managed databases and AI services.',
        findingTitles: [
          'PostgreSQL Flexible Server has public network access enabled',
          'PostgreSQL Flexible Server does not use Microsoft Entra ID authentication',
          'MySQL Flexible Server has public network access enabled',
          'MySQL Flexible Server has no Microsoft Entra ID administrator configured',
          'Cognitive Services / AI account has public network access enabled',
          'Cognitive Services / AI account has no network access restrictions',
        ],
      },
      {
        id: 'HIPAA-164.312(b)-EXT',
        name: 'Audit Controls — All Systems',
        description: 'Implement audit controls across all systems that touch ePHI.',
        findingTitles: [
          'MySQL Flexible Server audit logging is not enabled',
          'Service Bus namespace has no diagnostic logs configured',
          'Event Hub namespace has no diagnostic logs configured',
          'Cognitive Services / AI account has no diagnostic logs configured',
          'API Management service has no diagnostic logs configured',
          'No Log Analytics workspace found in subscription',
          'Log Analytics workspace has insufficient data retention period',
          'Synapse SQL Pool auditing is disabled',
          'Azure Automation account has no diagnostic logs configured',
          'Azure IoT Hub has no diagnostic logs configured',
        ],
      },
      {
        id: 'HIPAA-164.308(a)(7)',
        name: 'Contingency Plan — Backup & Recovery',
        description: 'Establish policies for responding to emergencies, including data backup.',
        findingTitles: BACKUP_FINDINGS,
      },
      {
        id: 'HIPAA-164.312(e)(2)(ii)-EXT',
        name: 'Transmission Encryption — Compute & IoT',
        description: 'Ensure all compute and IoT services encrypt data in transit.',
        findingTitles: [
          ...FUNCTIONS_FINDINGS.filter(f => f.includes('HTTPS') || f.includes('TLS')),
          ...CONTAINER_APPS_FINDINGS.filter(f => f.includes('HTTP') || f.includes('TLS')),
          ...APP_GATEWAY_FINDINGS.filter(f => f.includes('TLS') || f.includes('HTTP')),
          ...IOT_HUB_FINDINGS.filter(f => f.includes('TLS')),
          ...SYNAPSE_FINDINGS.filter(f => f.includes('TDE') || f.includes('encryption')),
        ],
      },
    ],
  },
];

// ---------------------------------------------------------------------------
// Scoring engine
// ---------------------------------------------------------------------------

export function scoreAzureFrameworks(
  activeTitles: Set<string>,
  titleCounts: Map<string, number>,
): AzureFrameworkScore[] {
  return AZURE_FRAMEWORKS.map(fw => {
    let passing = 0, failing = 0, notEvaluated = 0;

    const controls: AzureControlResult[] = fw.controls.map(ctrl => {
      if (ctrl.findingTitles.length === 0) {
        notEvaluated++;
        return { ...ctrl, status: 'NOT_EVALUATED', failingFindings: 0 };
      }

      const failingCount = ctrl.findingTitles
        .filter(t => activeTitles.has(t))
        .reduce((sum, t) => sum + (titleCounts.get(t) ?? 0), 0);

      if (failingCount > 0) {
        failing++;
        return { ...ctrl, status: 'FAIL', failingFindings: failingCount };
      }

      passing++;
      return { ...ctrl, status: 'PASS', failingFindings: 0 };
    });

    const denominator = passing + failing;
    const score = denominator === 0 ? 100 : Math.round((passing / denominator) * 100);

    return {
      frameworkId:           fw.id,
      frameworkName:         fw.name,
      shortName:             fw.shortName,
      score,
      passingControls:       passing,
      failingControls:       failing,
      notEvaluatedControls:  notEvaluated,
      totalControls:         fw.controls.length,
      controls,
    };
  });
}
