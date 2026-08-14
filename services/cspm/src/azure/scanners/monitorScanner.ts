// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

interface ActivityLogAlertLeafCondition {
  field?: string;
  equals?: string;
}

interface ActivityLogAlertLike {
  id?: string;
  name?: string;
  enabled?: boolean;
  description?: string;
  condition?: { allOf?: ActivityLogAlertLeafCondition[] };
}

interface DiagnosticSettingLike {
  id?: string;
  name?: string;
  storageAccountId?: string;
  workspaceId?: string;
  logs?: { category?: string; enabled: boolean }[];
}

/**
 * Returns true when `alertRule` is enabled and has a leaf condition
 * `operationName == expectedEqual` among its `allOf` conditions.
 * Mirrors Prowler's monitor_alerts.check_alert_rule().
 */
function checkAlertRule(alertRule: ActivityLogAlertLike, expectedEqual: string): boolean {
  if (!alertRule.enabled) return false;
  return (alertRule.condition?.allOf ?? []).some(
    (c) => c.field === 'operationName' && c.equals === expectedEqual,
  );
}

export class AzureMonitorScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-Monitor');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const monitorClient = this.client.monitor();
      const subscriptionId = this.client.subscriptionId;

      const alertRules: ActivityLogAlertLike[] = [];
      for await (const rule of monitorClient.activityLogAlerts.listBySubscriptionId()) {
        alertRules.push(rule);
      }

      this.scanActivityLogAlerts(findings, alertRules, subscriptionId);

      let diagnosticSettings: DiagnosticSettingLike[] = [];
      try {
        const resourceUri = `subscriptions/${subscriptionId}/`;
        const result = await monitorClient.diagnosticSettings.list(resourceUri);
        diagnosticSettings = (result.value ?? []) as DiagnosticSettingLike[];
      } catch (error) {
        // Diagnostic settings may be unreachable independent of alert rules — treat as optional.
        diagnosticSettings = [];
      }

      this.scanDiagnosticSettings(findings, diagnosticSettings, subscriptionId);
      await this.scanActivityLogStorageAccounts(findings, diagnosticSettings, subscriptionId);
    } catch (err) {
      findings.push(this.emit(
        'monitor_diagnostic_settings_exists',
        { error: (err as Error).message },
        {
          severity: 'INFO',
          message: `Azure Monitor scan error: could not complete the scan (${(err as Error).message})`,
          remediation: 'Ensure the service principal has Reader access to Microsoft.Insights (activityLogAlerts, diagnosticSettings) at the subscription scope.',
        },
      ));
    }

    return findings;
  }

  /**
   * The 6 create/update+delete alert-rule pairs, plus Service Health,
   * are each "PASS if any enabled alert rule matches, else FAIL" —
   * same one-finding-per-subscription shape as Prowler.
   */
  private scanActivityLogAlerts(
    findings: ScanningResult[],
    alertRules: ActivityLogAlertLike[],
    subscriptionId: string,
  ): void {
    const subjectEvidence = { subscriptionId, alertRuleCount: alertRules.length };

    const operationChecks: { checkId: string; operationNames: string[]; label: string }[] = [
      {
        checkId: 'monitor_alert_create_policy_assignment',
        operationNames: ['Microsoft.Authorization/policyAssignments/write'],
        label: 'creating Policy Assignments',
      },
      {
        checkId: 'monitor_alert_create_update_nsg',
        operationNames: ['Microsoft.Network/networkSecurityGroups/write'],
        label: 'creating/updating Network Security Groups',
      },
      {
        checkId: 'monitor_alert_create_update_public_ip_address_rule',
        operationNames: ['Microsoft.Network/publicIPAddresses/write'],
        label: 'creating/updating Public IP addresses',
      },
      {
        checkId: 'monitor_alert_create_update_security_solution',
        operationNames: ['Microsoft.Security/securitySolutions/write'],
        label: 'creating/updating Security Solutions',
      },
      {
        checkId: 'monitor_alert_create_update_sqlserver_fr',
        operationNames: ['Microsoft.Sql/servers/firewallRules/write'],
        label: 'creating/updating SQL Server firewall rules',
      },
      {
        checkId: 'monitor_alert_delete_nsg',
        operationNames: [
          'Microsoft.Network/networkSecurityGroups/delete',
          'Microsoft.ClassicNetwork/networkSecurityGroups/delete',
        ],
        label: 'deleting Network Security Groups',
      },
      {
        checkId: 'monitor_alert_delete_policy_assignment',
        operationNames: ['Microsoft.Authorization/policyAssignments/delete'],
        label: 'deleting Policy Assignments',
      },
      {
        checkId: 'monitor_alert_delete_public_ip_address_rule',
        operationNames: ['Microsoft.Network/publicIPAddresses/delete'],
        label: 'deleting Public IP addresses',
      },
      {
        checkId: 'monitor_alert_delete_security_solution',
        operationNames: ['Microsoft.Security/securitySolutions/delete'],
        label: 'deleting Security Solutions',
      },
      {
        checkId: 'monitor_alert_delete_sqlserver_fr',
        operationNames: ['Microsoft.Sql/servers/firewallRules/delete'],
        label: 'deleting SQL Server firewall rules',
      },
    ];

    for (const { checkId, operationNames, label } of operationChecks) {
      const matched = alertRules.find((rule) =>
        operationNames.some((op) => checkAlertRule(rule, op)),
      );

      if (matched) {
        findings.push(this.emit(
          checkId,
          { subscriptionId, alertRuleName: matched.name, alertRuleId: matched.id },
          { message: `Activity Log alert "${matched.name}" is configured for ${label} in subscription ${subscriptionId}.` },
        ));
      } else {
        findings.push(this.emit(
          checkId,
          subjectEvidence,
          {
            message: `There is no enabled Activity Log alert for ${label} in subscription ${subscriptionId}.`,
          },
        ));
      }
    }

    // Service Health: enabled alert rule with category=ServiceHealth AND properties.incidentType=Incident.
    const serviceHealthRule = alertRules.find((rule) => {
      if (!rule.enabled) return false;
      const conditions = rule.condition?.allOf ?? [];
      const hasServiceHealthCategory = conditions.some(
        (c) => c.field === 'category' && c.equals === 'ServiceHealth',
      );
      const hasIncidentType = conditions.some(
        (c) => c.field === 'properties.incidentType' && c.equals === 'Incident',
      );
      return hasServiceHealthCategory && hasIncidentType;
    });

    if (serviceHealthRule) {
      findings.push(this.emit(
        'monitor_alert_service_health_exists',
        { subscriptionId, alertRuleName: serviceHealthRule.name, alertRuleId: serviceHealthRule.id },
        { message: `Activity Log alert "${serviceHealthRule.name}" covers Service Health incidents in subscription ${subscriptionId}.` },
      ));
    } else {
      findings.push(this.emit(
        'monitor_alert_service_health_exists',
        subjectEvidence,
        { message: `There is no enabled Activity Log alert for Service Health incidents in subscription ${subscriptionId}.` },
      ));
    }
  }

  private scanDiagnosticSettings(
    findings: ScanningResult[],
    diagnosticSettings: DiagnosticSettingLike[],
    subscriptionId: string,
  ): void {
    // monitor_diagnostic_settings_exists: at least one diagnostic setting exists at all.
    if (diagnosticSettings.length > 0) {
      const setting = diagnosticSettings[0];
      findings.push(this.emit(
        'monitor_diagnostic_settings_exists',
        { subscriptionId, settingName: setting.name, settingId: setting.id },
        { message: `Activity Log diagnostic setting "${setting.name}" exists in subscription ${subscriptionId}.` },
      ));
    } else {
      findings.push(this.emit(
        'monitor_diagnostic_settings_exists',
        { subscriptionId },
        { message: `No Activity Log diagnostic settings are configured in subscription ${subscriptionId}.` },
      ));
    }

    // monitor_diagnostic_setting_with_appropriate_categories: at least one setting
    // must have Administrative + Security + Alert + Policy all enabled.
    const compliantSetting = diagnosticSettings.find((setting) => {
      const logs = setting.logs ?? [];
      const enabledCategories = new Set(
        logs.filter((l) => l.enabled).map((l) => l.category),
      );
      return (
        enabledCategories.has('Administrative') &&
        enabledCategories.has('Security') &&
        enabledCategories.has('Alert') &&
        enabledCategories.has('Policy')
      );
    });

    if (compliantSetting) {
      findings.push(this.emit(
        'monitor_diagnostic_setting_with_appropriate_categories',
        { subscriptionId, settingName: compliantSetting.name, settingId: compliantSetting.id },
        { message: `Diagnostic setting "${compliantSetting.name}" captures the Administrative, Security, Alert, and Policy categories in subscription ${subscriptionId}.` },
      ));
    } else {
      findings.push(this.emit(
        'monitor_diagnostic_setting_with_appropriate_categories',
        { subscriptionId },
        { message: `No diagnostic setting in subscription ${subscriptionId} captures all of the Administrative, Security, Alert, and Policy categories.` },
      ));
    }
  }

  /**
   * For every diagnostic setting that exports to a storage account, cross-reference
   * the storage account's encryption key source and public blob access setting.
   * Emits one finding per (diagnostic setting, matching storage account) pair,
   * matching Prowler's per-storage-account report shape.
   */
  private async scanActivityLogStorageAccounts(
    findings: ScanningResult[],
    diagnosticSettings: DiagnosticSettingLike[],
    subscriptionId: string,
  ): Promise<void> {
    const settingsWithStorage = diagnosticSettings.filter((s) => s.storageAccountId);
    if (settingsWithStorage.length === 0) return;

    try {
      const storageClient = this.client.storage();
      const accounts: any[] = [];
      for await (const sa of storageClient.storageAccounts.list()) accounts.push(sa);

      for (const setting of settingsWithStorage) {
        const storageAccountName = setting.storageAccountId!.split('/').pop();
        const account = accounts.find((sa) => sa.name === storageAccountName);
        if (!account) continue;

        const name = account.name ?? storageAccountName;
        const rg = account.id?.split('/')[4] ?? 'unknown';

        // monitor_storage_account_with_activity_logs_cmk_encrypted
        const keySource = account.encryption?.keySource ?? 'Microsoft.Storage';
        if (keySource === 'Microsoft.Storage') {
          findings.push(this.emit(
            'monitor_storage_account_with_activity_logs_cmk_encrypted',
            { account: name, resourceGroup: rg, keySource, subscriptionId },
            { message: `Storage account "${name}" storing Activity Logs in subscription ${subscriptionId} is not encrypted with a customer-managed key.` },
          ));
        }

        // monitor_storage_account_with_activity_logs_is_private
        if (account.allowBlobPublicAccess === true) {
          findings.push(this.emit(
            'monitor_storage_account_with_activity_logs_is_private',
            { account: name, resourceGroup: rg, subscriptionId },
            { message: `Storage account "${name}" storing Activity Logs in subscription ${subscriptionId} allows public blob access.` },
          ));
        }
      }
    } catch {
      // Storage cross-reference is optional — the alert-rule and diagnostic-setting
      // checks above are unaffected if the Storage Management client is unreachable.
    }
  }
}

export default AzureMonitorScanner;
