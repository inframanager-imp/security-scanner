import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureSynapseScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-Synapse');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const synapseClient = this.client.synapse();

      const workspaces: any[] = [];
      for await (const ws of synapseClient.workspaces.list()) workspaces.push(ws);

      if (workspaces.length === 0) return findings;

      for (const ws of workspaces) {
        const name = ws.name ?? 'unknown';
        const rg   = ws.id?.split('/')[4] ?? 'unknown';

        // 1. Public network access enabled
        const publicAccess = ws.publicNetworkAccess ?? 'Enabled';
        if (publicAccess === 'Enabled') {
          findings.push(this.finding(
            'Azure Synapse workspace has public network access enabled',
            `Synapse workspace "${name}" is accessible from the public internet. SQL pools, Spark pools, and the Synapse Studio are exposed to unauthorized connection attempts.`,
            'HIGH',
            { workspace: name, resourceGroup: rg },
            'Disable public network access on the Synapse workspace and use Private Endpoints for all connectivity to SQL pools, development endpoints, and the Synapse Studio.',
            ['synapse', 'network', 'public-access'],
          ));
        }

        // 2. Managed VNet not enabled
        const managedVNet = ws.managedVirtualNetwork;
        if (!managedVNet || managedVNet === 'default') {
          findings.push(this.finding(
            'Azure Synapse workspace does not use a managed virtual network',
            `Synapse workspace "${name}" has no managed VNet. Spark clusters and integration runtimes run on shared public infrastructure and may exfiltrate data to unintended destinations.`,
            'HIGH',
            { workspace: name, resourceGroup: rg },
            'Enable the managed virtual network when creating a Synapse workspace. Use Managed Private Endpoints to connect to ADLS Gen2, Key Vault, and other data sources.',
            ['synapse', 'network', 'managed-vnet'],
          ));
        }

        // 3. Azure AD-only authentication — no SQL authentication
        const aadOnlyAuth = ws.azureADOnlyAuthentication ?? false;
        if (!aadOnlyAuth) {
          findings.push(this.finding(
            'Azure Synapse workspace allows SQL authentication (not Entra ID only)',
            `Synapse workspace "${name}" allows legacy SQL username/password authentication. SQL credentials cannot benefit from MFA, Conditional Access, or centralized identity management.`,
            'HIGH',
            { workspace: name, resourceGroup: rg, azureADOnlyAuthentication: aadOnlyAuth },
            'Enable "Azure AD only authentication" on the Synapse workspace to disable local SQL authentication and require all users to authenticate via Microsoft Entra ID.',
            ['synapse', 'authentication', 'entra-id'],
          ));
        }

        // 4. Customer-managed key (CMK)
        const encryptionKey = ws.encryption?.cmk?.kekIdentity;
        if (!encryptionKey) {
          findings.push(this.finding(
            'Azure Synapse workspace does not use a customer-managed key for encryption',
            `Synapse workspace "${name}" uses Microsoft-managed keys for encryption of data at rest. CMK provides full control over encryption key lifecycle and enables key revocation.`,
            'MEDIUM',
            { workspace: name, resourceGroup: rg },
            'Configure a customer-managed key from Azure Key Vault for the Synapse workspace encryption settings.',
            ['synapse', 'encryption', 'cmk'],
          ));
        }

        // 5. SQL pools — TDE
        try {
          const sqlPools: any[] = [];
          for await (const pool of synapseClient.sqlPools.listByWorkspace(rg, name)) sqlPools.push(pool);

          for (const pool of sqlPools) {
            try {
              const tde = await synapseClient.sqlPoolTransparentDataEncryptions.get(
                rg, name, pool.name!, 'current',
              );
              if (tde.status !== 'Enabled') {
                findings.push(this.finding(
                  'Synapse SQL Pool has Transparent Data Encryption (TDE) disabled',
                  `Synapse SQL Pool "${pool.name}" in workspace "${name}" has TDE disabled. Data at rest in the SQL pool is not encrypted, violating most compliance frameworks.`,
                  'CRITICAL',
                  { workspace: name, sqlPool: pool.name, resourceGroup: rg, tdeStatus: tde.status },
                  'Enable Transparent Data Encryption on the Synapse SQL Pool.',
                  ['synapse', 'sql-pool', 'encryption'],
                ));
              }
            } catch { /* optional */ }

            // SQL pool auditing
            try {
              const auditing = await synapseClient.sqlPoolBlobAuditingPolicies.get(rg, name, pool.name!);
              if (auditing.state !== 'Enabled') {
                findings.push(this.finding(
                  'Synapse SQL Pool auditing is disabled',
                  `Synapse SQL Pool "${pool.name}" in workspace "${name}" has auditing disabled. SQL query history and access patterns cannot be reviewed for unauthorized activity.`,
                  'HIGH',
                  { workspace: name, sqlPool: pool.name, resourceGroup: rg },
                  'Enable auditing on the Synapse SQL Pool and configure a retention period of at least 90 days.',
                  ['synapse', 'sql-pool', 'auditing'],
                ));
              }
            } catch { /* optional */ }
          }
        } catch { /* optional */ }

        // 6. Firewall rules — check for open rules
        try {
          const rules: any[] = [];
          for await (const rule of synapseClient.ipFirewallRules.listByWorkspace(rg, name)) rules.push(rule);

          const openRule = rules.find(r =>
            r.startIpAddress === '0.0.0.0' && r.endIpAddress === '255.255.255.255',
          );
          if (openRule) {
            findings.push(this.finding(
              'Azure Synapse workspace firewall allows access from all IP addresses',
              `Synapse workspace "${name}" has a firewall rule allowing 0.0.0.0–255.255.255.255. Any internet host can attempt to connect to Synapse SQL endpoints.`,
              'CRITICAL',
              { workspace: name, resourceGroup: rg, rule: openRule.name },
              'Remove the open-range firewall rule. Use specific IP ranges or disable public access and use Private Endpoint.',
              ['synapse', 'firewall'],
            ));
          }

          const allowAzureServices = rules.find(r =>
            r.startIpAddress === '0.0.0.0' && r.endIpAddress === '0.0.0.0',
          );
          if (allowAzureServices) {
            findings.push(this.finding(
              'Azure Synapse workspace firewall allows all Azure services',
              `Synapse workspace "${name}" has an "Allow Azure services" rule (0.0.0.0–0.0.0.0). This permits any Azure-hosted service (including other tenants) to connect to the workspace.`,
              'MEDIUM',
              { workspace: name, resourceGroup: rg },
              'Remove the "Allow Azure services" rule. Use Managed Private Endpoints or specific IP allow-list rules instead.',
              ['synapse', 'firewall'],
            ));
          }
        } catch { /* optional */ }

        // 7. Diagnostic logs
        try {
          const monitorClient = this.client.monitor();
          const settingsResult = await monitorClient.diagnosticSettings.list(ws.id!);
          const settings: any[] = settingsResult.value ?? [];
          const hasLogs = settings.some(s =>
            s.logs?.some((l: any) => l.enabled) || s.metrics?.some((m: any) => m.enabled),
          );
          if (!hasLogs) {
            findings.push(this.finding(
              'Azure Synapse workspace has no diagnostic logs configured',
              `Synapse workspace "${name}" has no diagnostic settings. Without logs, SQL pool queries, Spark job runs, and integration runtime activity cannot be audited.`,
              'MEDIUM',
              { workspace: name, resourceGroup: rg },
              'Enable diagnostic settings to capture SynapseRbacOperations, GatewayApiRequests, BuiltinSqlReqsEnded, and IntegrationPipelineRuns logs to a Log Analytics workspace.',
              ['synapse', 'logging'],
            ));
          }
        } catch { /* optional */ }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Synapse Analytics scan error',
        `Could not complete Synapse workspace scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Synapse Analytics resources.',
      ));
    }

    return findings;
  }
}
