import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureAutomationScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-Automation');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const automationClient = this.client.automation();

      const accounts: any[] = [];
      let acctPage: any = await automationClient.automationAccount.list();
      accounts.push(...acctPage);
      while (acctPage.nextLink) {
        acctPage = await automationClient.automationAccount.listNext(acctPage.nextLink);
        accounts.push(...acctPage);
      }

      if (accounts.length === 0) return findings;

      for (const acct of accounts) {
        const name = acct.name ?? 'unknown';
        const rg   = acct.id?.split('/')[4] ?? 'unknown';

        // 1. Public network access enabled
        const publicAccess = acct.publicNetworkAccess ?? true;
        if (publicAccess !== false) {
          findings.push(this.finding(
            'Azure Automation account has public network access enabled',
            `Automation account "${name}" is accessible from the public internet. Runbooks, credentials, and connection assets are exposed to unauthorized access attempts with stolen credentials.`,
            'HIGH',
            { account: name, resourceGroup: rg },
            'Disable public network access on the Automation account and use Private Endpoints to allow access only from trusted VNets.',
            ['automation', 'network', 'public-access'],
          ));
        }

        // 2. Managed identity not assigned — check for Run As account (legacy)
        const hasManagedIdentity = acct.identity?.type &&
          (acct.identity.type.includes('SystemAssigned') || acct.identity.type.includes('UserAssigned'));
        if (!hasManagedIdentity) {
          findings.push(this.finding(
            'Azure Automation account does not use managed identity (Run As account risk)',
            `Automation account "${name}" has no managed identity configured. Without managed identity, runbooks must use the legacy "Run As Account" (which uses a service principal with a certificate that must be manually renewed) or embed credentials in runbooks.`,
            'HIGH',
            { account: name, resourceGroup: rg },
            'Enable system-assigned managed identity on the Automation account. Grant it the minimum required RBAC roles. Migrate all runbooks from Run As Account to Managed Identity authentication.',
            ['automation', 'identity', 'run-as-account'],
          ));
        }

        // 3. Customer-managed key (CMK)
        const encryptionKey = acct.encryption?.keySource;
        if (!encryptionKey || encryptionKey === 'Microsoft.Automation') {
          findings.push(this.finding(
            'Azure Automation account does not use a customer-managed encryption key',
            `Automation account "${name}" uses Microsoft-managed keys for encrypting variables, credentials, and certificates. CMK provides control over key lifecycle and revocation.`,
            'MEDIUM',
            { account: name, resourceGroup: rg },
            'Configure a customer-managed key for the Automation account encryption settings using an Azure Key Vault key.',
            ['automation', 'encryption', 'cmk'],
          ));
        }

        // 4. Runbook content review — check for potentially sensitive runbooks
        try {
          const runbooks: any[] = [];
          let rbPage: any = await automationClient.runbook.listByAutomationAccount(rg, name);
          runbooks.push(...rbPage);
          while (rbPage.nextLink) {
            rbPage = await automationClient.runbook.listByAutomationAccountNext(rbPage.nextLink);
            runbooks.push(...rbPage);
          }

          for (const rb of runbooks) {
            // Flag if draft runbooks exist in production (not published = untested)
            if (rb.state === 'Edit') {
              findings.push(this.finding(
                'Azure Automation account has unpublished (draft) runbooks',
                `Automation account "${name}" runbook "${rb.name}" is in draft state. Draft runbooks have not been reviewed or tested and may contain errors or security issues.`,
                'LOW',
                { account: name, runbook: rb.name, resourceGroup: rg, state: rb.state },
                'Review and either publish or delete all draft runbooks. Implement a code review process before publishing runbooks to production.',
                ['automation', 'runbook'],
              ));
            }
          }
        } catch { /* optional */ }

        // 5. Variables — check for unencrypted variables
        try {
          const variables: any[] = [];
          let vPage: any = await automationClient.variable.listByAutomationAccount(rg, name);
          variables.push(...vPage);
          while (vPage.nextLink) {
            vPage = await automationClient.variable.listByAutomationAccountNext(vPage.nextLink);
            variables.push(...vPage);
          }

          const unencryptedSensitive = variables.filter(v =>
            !v.isEncrypted &&
            (v.name?.toLowerCase().includes('password') ||
             v.name?.toLowerCase().includes('secret') ||
             v.name?.toLowerCase().includes('key') ||
             v.name?.toLowerCase().includes('token') ||
             v.name?.toLowerCase().includes('credential')),
          );
          if (unencryptedSensitive.length > 0) {
            findings.push(this.finding(
              'Azure Automation account has unencrypted variables with sensitive names',
              `Automation account "${name}" has ${unencryptedSensitive.length} unencrypted variable(s) with names suggesting sensitive data: ${unencryptedSensitive.slice(0, 5).map(v => v.name).join(', ')}. Unencrypted variables are stored in plaintext and visible to all users with Reader access.`,
              'HIGH',
              { account: name, resourceGroup: rg, count: unencryptedSensitive.length },
              'Mark all sensitive variables as encrypted. Use Azure Key Vault for secrets instead of Automation variables when possible.',
              ['automation', 'secrets'],
            ));
          }
        } catch { /* optional */ }

        // 6. Diagnostic logs
        try {
          const monitorClient = this.client.monitor();
          const settingsResult = await monitorClient.diagnosticSettings.list(acct.id!);
          const settings: any[] = settingsResult.value ?? [];
          const hasLogs = settings.some(s =>
            s.logs?.some((l: any) => l.enabled) || s.metrics?.some((m: any) => m.enabled),
          );
          if (!hasLogs) {
            findings.push(this.finding(
              'Azure Automation account has no diagnostic logs configured',
              `Automation account "${name}" has no diagnostic settings. Without logs, runbook executions, job failures, and schedule changes cannot be audited.`,
              'MEDIUM',
              { account: name, resourceGroup: rg },
              'Enable diagnostic settings to capture JobLogs, JobStreams, and AuditEvent logs to a Log Analytics workspace.',
              ['automation', 'logging'],
            ));
          }
        } catch { /* optional */ }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Automation scan error',
        `Could not complete Automation account scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Automation account resources.',
      ));
    }

    return findings;
  }
}
