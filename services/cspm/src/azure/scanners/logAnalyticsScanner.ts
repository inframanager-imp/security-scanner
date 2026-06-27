import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureLogAnalyticsScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-LogAnalytics');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const oiClient = this.client.operationalInsights();

      const workspaces: any[] = [];
      for await (const ws of oiClient.workspaces.list()) workspaces.push(ws);

      if (workspaces.length === 0) {
        // No Log Analytics workspace is itself a critical finding
        findings.push(this.finding(
          'No Log Analytics workspace found in subscription',
          'The subscription has no Log Analytics workspace. Without a central log collection point, security monitoring, threat detection, and compliance auditing are not possible across Azure resources.',
          'CRITICAL',
          { subscriptionId: this.client.subscriptionId },
          'Create a Log Analytics workspace and configure all Azure resources (VMs, storage accounts, Key Vaults, NSGs, etc.) to send diagnostic logs to it. Enable Microsoft Sentinel or Azure Monitor alert rules on the workspace.',
          ['loganalytics', 'monitoring', 'visibility'],
        ));
        return findings;
      }

      for (const ws of workspaces) {
        const name = ws.name ?? 'unknown';
        const rg   = ws.id?.split('/')[4] ?? 'unknown';

        // 1. Data retention too short
        const retention = ws.retentionInDays ?? 30;
        if (retention < 90) {
          findings.push(this.finding(
            'Log Analytics workspace has insufficient data retention period',
            `Log Analytics workspace "${name}" retains data for only ${retention} days. Most compliance frameworks (PCI-DSS, HIPAA, SOC 2) require at least 90 days of online log retention and 1 year of total retention.`,
            'HIGH',
            { workspace: name, resourceGroup: rg, retentionInDays: retention },
            'Set the workspace retention to at least 90 days. For compliance, configure archive retention (up to 12 years) for data older than the interactive retention window.',
            ['loganalytics', 'data-retention', 'compliance'],
          ));
        }

        // 2. Public access enabled (query and ingestion over internet)
        const publicIngestion = ws.publicNetworkAccessForIngestion ?? 'Enabled';
        const publicQuery     = ws.publicNetworkAccessForQuery ?? 'Enabled';
        if (publicIngestion === 'Enabled' || publicQuery === 'Enabled') {
          findings.push(this.finding(
            'Log Analytics workspace allows public network access for ingestion or query',
            `Log Analytics workspace "${name}" has public access enabled for: ${[
              publicIngestion === 'Enabled' && 'ingestion',
              publicQuery === 'Enabled' && 'query',
            ].filter(Boolean).join(', ')}. Log data in transit over the public internet can be intercepted or the endpoint can be targeted for data poisoning.`,
            'MEDIUM',
            { workspace: name, resourceGroup: rg, publicIngestion, publicQuery },
            'Disable public network access for both ingestion and query. Use Private Link Scopes (Azure Monitor Private Link Scope) to route log ingestion through a VNet.',
            ['loganalytics', 'network', 'public-access'],
          ));
        }

        // 3. Customer-managed key (CMK)
        const clusterResourceId = (ws as any).clusterResourceId;
        if (!clusterResourceId) {
          findings.push(this.finding(
            'Log Analytics workspace does not use a customer-managed key',
            `Log Analytics workspace "${name}" uses Microsoft-managed keys for encrypting log data. Without CMK, revocation of access to stored log data is not possible.`,
            'MEDIUM',
            { workspace: name, resourceGroup: rg, sku: ws.sku?.name },
            'Associate the workspace with a Log Analytics Cluster that has CMK configured via a Key Vault-backed key. This requires a Capacity Reservation commitment tier.',
            ['loganalytics', 'encryption', 'cmk'],
          ));
        }

        // 4. No data export rules (data sovereignty / archival)
        try {
          const exportRules: any[] = [];
          for await (const rule of oiClient.dataExports.listByWorkspace(rg, name)) exportRules.push(rule);

          if (exportRules.length === 0) {
            findings.push(this.finding(
              'Log Analytics workspace has no data export rules configured',
              `Log Analytics workspace "${name}" has no data export rules. Long-term log archival for compliance and forensic investigation relies solely on workspace retention, which has a maximum of 12 years.`,
              'LOW',
              { workspace: name, resourceGroup: rg },
              'Configure data export rules to continuously export selected log tables to Azure Storage (for long-term archival) or Event Hub (for SIEM integration).',
              ['loganalytics', 'data-retention'],
            ));
          }
        } catch { /* optional */ }

        // 5. Workspace access mode — require resource-level RBAC
        const accessMode = ws.features?.enableLogAccessUsingOnlyResourcePermissions;
        if (accessMode === false || accessMode === undefined) {
          findings.push(this.finding(
            'Log Analytics workspace allows workspace-level access (not resource-context mode)',
            `Log Analytics workspace "${name}" is in workspace access mode, allowing any user with Workspace Reader role to read all logs regardless of which resource generated them. This may expose logs from security-sensitive resources.`,
            'MEDIUM',
            { workspace: name, resourceGroup: rg },
            'Enable resource-context access mode (enableLogAccessUsingOnlyResourcePermissions = true) so users can only query logs for resources they already have RBAC access to.',
            ['loganalytics', 'access-control'],
          ));
        }

        // 6. Daily cap set too low (log ingestion may be silently dropped)
        const dailyCap = (ws as any).workspaceCapping?.dailyQuotaGb ?? -1;
        if (dailyCap !== -1 && dailyCap < 1) {
          findings.push(this.finding(
            'Log Analytics workspace has a very low daily ingestion cap',
            `Log Analytics workspace "${name}" has a daily cap of ${dailyCap} GB. When the cap is reached, log ingestion silently stops for the remainder of the day, creating security blind spots.`,
            'MEDIUM',
            { workspace: name, resourceGroup: rg, dailyQuotaGb: dailyCap },
            'Increase the daily ingestion cap to match your expected log volume. Configure alerts to notify when 80% of the daily cap is reached.',
            ['loganalytics', 'availability'],
          ));
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Log Analytics scan error',
        `Could not complete Log Analytics workspace scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Log Analytics workspaces.',
      ));
    }

    return findings;
  }
}
