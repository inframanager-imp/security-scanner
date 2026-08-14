// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
/**
 * Azure Defender for Cloud (Microsoft Defender) Scanner
 *
 * Calls the Azure Resource Manager "Microsoft.Security" REST provider directly
 * using the service principal credential — the same native-fetch-with-ARM-token
 * pattern entraScanner.ts uses for Microsoft Graph. No @azure/arm-security SDK
 * client is wired into AzureClient (it is not an existing dependency), so this
 * scanner talks to the REST API directly rather than adding a new npm package
 * for a handful of read-only list calls.
 *
 * Required RBAC: Reader (or Security Reader) on the subscription is sufficient
 * for all endpoints used below.
 */

import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const ARM_BASE = 'https://management.azure.com';

interface Pricing {
  name: string;
  id: string;
  pricingTier: string;
  extensions: Record<string, boolean>;
}

interface AutoProvisioningSetting {
  name: string;
  id: string;
  autoProvision: string;
}

interface Assessment {
  name: string;
  id: string;
  displayName: string;
  status: string;
}

interface Setting {
  name: string;
  id: string;
  kind: string;
  enabled: boolean;
}

interface SecurityContact {
  name: string;
  id: string;
  enabled: boolean;
  emails: string[];
  notificationsByRoleState: boolean;
  notificationsByRoleRoles: string[];
  attackPathMinimalRiskLevel: string | null;
  alertMinimalSeverity: string | null;
}

interface IoTSecuritySolution {
  name: string;
  id: string;
  status: string;
}

const RISK_LEVELS = ['Low', 'Medium', 'High', 'Critical'];
const MIN_RISK_LEVEL_DEFAULT = 'High';

export class AzureDefenderScanner extends AzureBaseScanner {
  private armToken: string | null = null;

  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-Defender');
  }

  private async getArmToken(): Promise<string | null> {
    if (this.armToken) return this.armToken;
    try {
      const tokenResponse = await this.client.credential.getToken('https://management.azure.com/.default');
      this.armToken = tokenResponse?.token ?? null;
      return this.armToken;
    } catch {
      return null;
    }
  }

  private async armGet(path: string): Promise<any> {
    const token = await this.getArmToken();
    if (!token) throw new Error('Unable to obtain Azure ARM token — check service principal credentials');

    const res = await fetch(`${ARM_BASE}${path}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`ARM API ${path} returned ${res.status}: ${body.slice(0, 200)}`);
    }

    return res.json();
  }

  private get subscriptionId(): string {
    return (this.client as any).subscriptionId;
  }

  // ---- data collection -----------------------------------------------

  private async listPricings(): Promise<Map<string, Pricing>> {
    const data = await this.armGet(
      `/subscriptions/${this.subscriptionId}/providers/Microsoft.Security/pricings?api-version=2024-01-01`,
    );
    const map = new Map<string, Pricing>();
    for (const p of data.value ?? []) {
      const extensions: Record<string, boolean> = {};
      for (const ext of p.properties?.extensions ?? []) {
        extensions[ext.name] = ext.isEnabled === 'True' || ext.isEnabled === true;
      }
      map.set(p.name, {
        name: p.name,
        id: p.id,
        pricingTier: p.properties?.pricingTier ?? 'Free',
        extensions,
      });
    }
    return map;
  }

  private async listAutoProvisioningSettings(): Promise<AutoProvisioningSetting[]> {
    const data = await this.armGet(
      `/subscriptions/${this.subscriptionId}/providers/Microsoft.Security/autoProvisioningSettings?api-version=2017-08-01-preview`,
    );
    return (data.value ?? []).map((a: any) => ({
      name: a.name,
      id: a.id,
      autoProvision: a.properties?.autoProvision ?? 'Off',
    }));
  }

  private async listAssessments(): Promise<Map<string, Assessment>> {
    const data = await this.armGet(
      `/subscriptions/${this.subscriptionId}/providers/Microsoft.Security/assessments?api-version=2021-06-01`,
    );
    const map = new Map<string, Assessment>();
    for (const a of data.value ?? []) {
      const displayName = a.properties?.displayName;
      if (!displayName) continue;
      map.set(displayName, {
        name: a.name,
        id: a.id,
        displayName,
        status: a.properties?.status?.code ?? 'Unknown',
      });
    }
    return map;
  }

  private async listSettings(): Promise<Map<string, Setting>> {
    const data = await this.armGet(
      `/subscriptions/${this.subscriptionId}/providers/Microsoft.Security/settings?api-version=2022-05-01`,
    );
    const map = new Map<string, Setting>();
    for (const s of data.value ?? []) {
      map.set(s.name, {
        name: s.name,
        id: s.id,
        kind: s.kind,
        enabled: s.properties?.enabled === true,
      });
    }
    return map;
  }

  private async listSecurityContacts(): Promise<SecurityContact[]> {
    const data = await this.armGet(
      `/subscriptions/${this.subscriptionId}/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview`,
    );
    return (data.value ?? []).map((c: any) => {
      const props = c.properties ?? {};
      const notificationsByRole = props.notificationsByRole ?? {};
      let attackPathMinimalRiskLevel: string | null = null;
      let alertMinimalSeverity: string | null = null;
      for (const source of props.notificationsSources ?? []) {
        if (source.sourceType === 'AttackPath' && source.minimalRiskLevel) {
          attackPathMinimalRiskLevel = source.minimalRiskLevel;
        } else if (source.sourceType === 'Alert' && source.minimalSeverity) {
          alertMinimalSeverity = source.minimalSeverity;
        }
      }
      return {
        name: c.name ?? 'default',
        id: c.id ?? '',
        enabled: props.isEnabled === true,
        emails: (props.emails ?? '').split(';').filter((e: string) => e.length > 0),
        notificationsByRoleState: String(notificationsByRole.state ?? 'Off').toLowerCase() === 'on',
        notificationsByRoleRoles: notificationsByRole.roles ?? [],
        attackPathMinimalRiskLevel,
        alertMinimalSeverity,
      };
    });
  }

  private async listIoTSecuritySolutions(): Promise<IoTSecuritySolution[]> {
    const data = await this.armGet(
      `/subscriptions/${this.subscriptionId}/providers/Microsoft.Security/iotSecuritySolutions?api-version=2019-08-01`,
    );
    return (data.value ?? []).map((s: any) => ({
      name: s.name,
      id: s.id,
      status: s.properties?.status ?? 'Unknown',
    }));
  }

  // ---- checks -----------------------------------------------------------

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const [pricings, autoProvisioning, assessments, settings, securityContacts, iotSolutions] =
        await Promise.all([
          this.listPricings().catch(() => new Map<string, Pricing>()),
          this.listAutoProvisioningSettings().catch(() => [] as AutoProvisioningSetting[]),
          this.listAssessments().catch(() => new Map<string, Assessment>()),
          this.listSettings().catch(() => new Map<string, Setting>()),
          this.listSecurityContacts().catch(() => [] as SecurityContact[]),
          this.listIoTSecuritySolutions().catch(() => [] as IoTSecuritySolution[]),
        ]);

      this.checkPricingTiers(findings, pricings);
      this.checkContainerImageScanning(findings, pricings);
      this.checkDefenderForDatabases(findings, pricings);
      this.checkAutoProvisioning(findings, autoProvisioning);
      this.checkAssessments(findings, assessments);
      this.checkMcasAndWdatp(findings, settings);
      this.checkSecurityContacts(findings, securityContacts);
      this.checkIoTHubDefender(findings, iotSolutions);
    } catch (err) {
      findings.push(this.finding(
        'Azure Defender scan error',
        `Could not complete Defender for Cloud scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader access on the subscription and Microsoft.Security is a registered resource provider.',
      ));
    }

    return findings;
  }

  /** Simple "pricing tier must be Standard" checks — one Defender plan each. */
  private checkPricingTiers(findings: ScanningResult[], pricings: Map<string, Pricing>): void {
    const plans: Array<{ key: string; checkId: string; label: string }> = [
      { key: 'CloudPosture', checkId: 'defender_ensure_defender_cspm_is_on', label: 'CSPM' },
      { key: 'AppServices', checkId: 'defender_ensure_defender_for_app_services_is_on', label: 'App Services' },
      { key: 'Arm', checkId: 'defender_ensure_defender_for_arm_is_on', label: 'Resource Manager' },
      { key: 'SqlServers', checkId: 'defender_ensure_defender_for_azure_sql_databases_is_on', label: 'Azure SQL Databases' },
      { key: 'Containers', checkId: 'defender_ensure_defender_for_containers_is_on', label: 'Containers' },
      { key: 'CosmosDbs', checkId: 'defender_ensure_defender_for_cosmosdb_is_on', label: 'Cosmos DB' },
      { key: 'Dns', checkId: 'defender_ensure_defender_for_dns_is_on', label: 'DNS' },
      { key: 'KeyVaults', checkId: 'defender_ensure_defender_for_keyvault_is_on', label: 'Key Vault' },
      { key: 'OpenSourceRelationalDatabases', checkId: 'defender_ensure_defender_for_os_relational_databases_is_on', label: 'Open-Source Relational Databases' },
      { key: 'VirtualMachines', checkId: 'defender_ensure_defender_for_server_is_on', label: 'Servers' },
      { key: 'SqlServerVirtualMachines', checkId: 'defender_ensure_defender_for_sql_servers_is_on', label: 'SQL Servers on Machines' },
      { key: 'StorageAccounts', checkId: 'defender_ensure_defender_for_storage_is_on', label: 'Storage' },
    ];

    for (const plan of plans) {
      const pricing = pricings.get(plan.key);
      if (!pricing) continue;

      if (pricing.pricingTier !== 'Standard') {
        findings.push(this.emit(
          plan.checkId,
          { plan: plan.key, pricingTier: pricing.pricingTier, resourceId: pricing.id },
          {
            message: `Defender plan "${plan.label}" is set to OFF (pricing tier "${pricing.pricingTier}", expected "Standard") for subscription ${this.subscriptionId}`,
          },
        ));
      }
    }
  }

  private checkContainerImageScanning(findings: ScanningResult[], pricings: Map<string, Pricing>): void {
    const containers = pricings.get('Containers');
    if (!containers) return;
    if (!containers.extensions['ContainerRegistriesVulnerabilityAssessments']) {
      findings.push(this.emit(
        'defender_container_images_scan_enabled',
        { plan: 'Containers', extensions: containers.extensions, resourceId: containers.id },
        {
          message: `Container image vulnerability scanning is disabled for subscription ${this.subscriptionId} (ContainerRegistriesVulnerabilityAssessments extension not enabled)`,
        },
      ));
    }
  }

  private checkDefenderForDatabases(findings: ScanningResult[], pricings: Map<string, Pricing>): void {
    const keys = ['SqlServers', 'SqlServerVirtualMachines', 'OpenSourceRelationalDatabases', 'CosmosDbs'];
    if (!keys.every((k) => pricings.has(k))) return;

    const offPlans = keys.filter((k) => pricings.get(k)!.pricingTier !== 'Standard');
    if (offPlans.length > 0) {
      findings.push(this.emit(
        'defender_ensure_defender_for_databases_is_on',
        { offPlans, tiers: Object.fromEntries(keys.map((k) => [k, pricings.get(k)!.pricingTier])) },
        {
          message: `Defender for Databases is not fully enabled for subscription ${this.subscriptionId} — sub-plan(s) not on Standard tier: ${offPlans.join(', ')}`,
        },
      ));
    }
  }

  private checkAutoProvisioning(findings: ScanningResult[], settings: AutoProvisioningSetting[]): void {
    for (const setting of settings) {
      if (setting.autoProvision !== 'On') {
        findings.push(this.emit(
          'defender_auto_provisioning_log_analytics_agent_vms_on',
          { setting: setting.name, autoProvision: setting.autoProvision, resourceId: setting.id },
          {
            message: `Defender auto-provisioning "${setting.name}" is set to OFF for subscription ${this.subscriptionId}`,
          },
        ));
      }
    }
  }

  private checkAssessments(findings: ScanningResult[], assessments: Map<string, Assessment>): void {
    const endpointProtection = assessments.get('Install endpoint protection solution on virtual machines');
    if (endpointProtection && endpointProtection.status === 'Unhealthy') {
      findings.push(this.emit(
        'defender_assessments_vm_endpoint_protection_installed',
        { resourceId: endpointProtection.id, status: endpointProtection.status },
        { message: `Endpoint protection is not installed on all VMs in subscription ${this.subscriptionId}` },
      ));
    }

    const vaAssessment = assessments.get('Machines should have a vulnerability assessment solution');
    if (vaAssessment && vaAssessment.status === 'Unhealthy') {
      findings.push(this.emit(
        'defender_auto_provisioning_vulnerabilty_assessments_machines_on',
        { resourceId: vaAssessment.id, status: vaAssessment.status },
        { message: `Vulnerability assessment is not set up on all VMs in subscription ${this.subscriptionId}` },
      ));
    }

    const containerVulns = assessments.get(
      'Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)',
    );
    if (containerVulns && containerVulns.status !== 'NotApplicable' && containerVulns.status === 'Unhealthy') {
      findings.push(this.emit(
        'defender_container_images_resolved_vulnerabilities',
        { resourceId: containerVulns.id, status: containerVulns.status },
        { message: `Running container images have unresolved vulnerabilities in subscription ${this.subscriptionId}` },
      ));
    }

    const logAnalyticsAgent = assessments.get('Log Analytics agent should be installed on virtual machines');
    const periodicCheck = assessments.get('Machines should be configured to periodically check for missing system updates');
    const systemUpdates = assessments.get('System updates should be installed on your machines');
    if (logAnalyticsAgent && periodicCheck && systemUpdates) {
      const unhealthy = [logAnalyticsAgent, periodicCheck, systemUpdates].some((a) => a.status === 'Unhealthy');
      if (unhealthy) {
        findings.push(this.emit(
          'defender_ensure_system_updates_are_applied',
          {
            logAnalyticsAgentStatus: logAnalyticsAgent.status,
            periodicCheckStatus: periodicCheck.status,
            systemUpdatesStatus: systemUpdates.status,
          },
          { message: `System updates are not applied to all VMs in subscription ${this.subscriptionId}` },
        ));
      }
    }
  }

  private checkMcasAndWdatp(findings: ScanningResult[], settings: Map<string, Setting>): void {
    const mcas = settings.get('MCAS');
    if (!mcas || !mcas.enabled) {
      findings.push(this.emit(
        'defender_ensure_mcas_is_enabled',
        { resourceId: mcas?.id, present: !!mcas },
        {
          message: mcas
            ? `Microsoft Defender for Cloud Apps integration is disabled for subscription ${this.subscriptionId}`
            : `Microsoft Defender for Cloud Apps integration does not exist for subscription ${this.subscriptionId}`,
        },
      ));
    }

    const wdatp = settings.get('WDATP');
    if (!wdatp || !wdatp.enabled) {
      findings.push(this.emit(
        'defender_ensure_wdatp_is_enabled',
        { resourceId: wdatp?.id, present: !!wdatp },
        {
          message: wdatp
            ? `Microsoft Defender for Endpoint integration is disabled for subscription ${this.subscriptionId}`
            : `Microsoft Defender for Endpoint integration does not exist for subscription ${this.subscriptionId}`,
        },
      ));
    }
  }

  private checkSecurityContacts(findings: ScanningResult[], contacts: SecurityContact[]): void {
    const minRiskLevel = MIN_RISK_LEVEL_DEFAULT;
    const minRiskIndex = RISK_LEVELS.indexOf(minRiskLevel);

    for (const contact of contacts) {
      // defender_additional_email_configured_with_a_security_contact
      if (contact.emails.length === 0) {
        findings.push(this.emit(
          'defender_additional_email_configured_with_a_security_contact',
          { contact: contact.name, resourceId: contact.id },
          { message: `Security contact "${contact.name}" has no additional email addresses configured for subscription ${this.subscriptionId}` },
        ));
      }

      // defender_attack_path_notifications_properly_configured
      const attackRiskLevel = contact.attackPathMinimalRiskLevel;
      if (!attackRiskLevel || !RISK_LEVELS.includes(attackRiskLevel)) {
        findings.push(this.emit(
          'defender_attack_path_notifications_properly_configured',
          { contact: contact.name, resourceId: contact.id },
          { message: `Attack path notifications are not enabled for security contact "${contact.name}" in subscription ${this.subscriptionId}` },
        ));
      } else {
        const actualIndex = RISK_LEVELS.indexOf(attackRiskLevel);
        if (actualIndex > minRiskIndex) {
          findings.push(this.emit(
            'defender_attack_path_notifications_properly_configured',
            { contact: contact.name, resourceId: contact.id, attackPathMinimalRiskLevel: attackRiskLevel },
            { message: `Attack path notifications for security contact "${contact.name}" are set to minimal risk level "${attackRiskLevel}", which is above the required threshold "${minRiskLevel}" in subscription ${this.subscriptionId}` },
          ));
        }
      }

      // defender_ensure_notify_alerts_severity_is_high
      if (!contact.alertMinimalSeverity || contact.alertMinimalSeverity === 'Critical') {
        findings.push(this.emit(
          'defender_ensure_notify_alerts_severity_is_high',
          { contact: contact.name, resourceId: contact.id, alertMinimalSeverity: contact.alertMinimalSeverity },
          { message: `Alert notifications for security contact "${contact.name}" are not enabled at High severity or lower in subscription ${this.subscriptionId}` },
        ));
      }

      // defender_ensure_notify_emails_to_owners
      if (!contact.notificationsByRoleState || !contact.notificationsByRoleRoles.includes('Owner')) {
        findings.push(this.emit(
          'defender_ensure_notify_emails_to_owners',
          { contact: contact.name, resourceId: contact.id, roles: contact.notificationsByRoleRoles },
          { message: `The Owner role is not notified by security contact "${contact.name}" in subscription ${this.subscriptionId}` },
        ));
      }
    }
  }

  private checkIoTHubDefender(findings: ScanningResult[], solutions: IoTSecuritySolution[]): void {
    if (solutions.length === 0) {
      findings.push(this.emit(
        'defender_ensure_iot_hub_defender_is_on',
        { subscriptionId: this.subscriptionId },
        { message: `No IoT Security Solutions found in subscription ${this.subscriptionId}` },
      ));
      return;
    }

    for (const solution of solutions) {
      if (solution.status !== 'Enabled') {
        findings.push(this.emit(
          'defender_ensure_iot_hub_defender_is_on',
          { solution: solution.name, status: solution.status, resourceId: solution.id },
          { message: `IoT Security Solution "${solution.name}" is disabled in subscription ${this.subscriptionId}` },
        ));
      }
    }
  }
}

export default AzureDefenderScanner;
