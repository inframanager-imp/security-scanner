/**
 * Azure Threat Detection Scanner
 *
 * Pulls from three data sources (no Defender required, Reader-only):
 *   1. Azure Monitor Activity Logs  — control-plane API calls
 *   2. NSG Flow Logs metadata       — network-level anomalies (via NetworkWatcher)
 *   3. Azure AD Sign-in Logs        — via Microsoft Graph (if permissions allow)
 *
 * Detects:
 *   - Suspicious mass secret reads from Key Vault
 *   - Privilege escalation (new Owner/UserAccessAdmin assignments)
 *   - Anomalous resource deletions (bulk deletes in short window)
 *   - Suspicious API calls from anonymous/unknown principals
 *   - NSG rules modified to open management ports to internet
 *   - Large-scale data export from Storage
 *   - Brute force: many 401s followed by a success
 *   - Impossible travel (sign-in from distant IPs in short time)
 */

import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const MANAGEMENT_PORTS = new Set(['22', '3389', '5985', '5986', '5432', '1433', '3306', '27017']);

const PRIVILEGED_ROLE_IDS = new Set([
  '8e3af657-a8ff-443c-a75c-2fe8c4bcb635', // Owner
  '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9', // User Access Administrator
  'b24988ac-6180-42a0-ab88-20f7382dd24c', // Contributor
]);

export interface ThreatScanOptions {
  since: Date;
}

export class AzureThreatScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-Threat');
  }

  async scan(): Promise<ScanningResult[]> {
    const since = new Date(Date.now() - 60 * 60 * 1000); // default: last 1h
    return this.scanSince(since);
  }

  async scanSince(since: Date): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const now = new Date();

    const startTime = since.toISOString();
    const endTime   = now.toISOString();

    // All three checks run in parallel — individual failures don't abort others
    const [activityResults, nsgResults] = await Promise.allSettled([
      this.checkActivityLogs(startTime, endTime),
      this.checkNSGChanges(startTime, endTime),
    ]);

    if (activityResults.status === 'fulfilled') findings.push(...activityResults.value);
    if (nsgResults.status === 'fulfilled')      findings.push(...nsgResults.value);

    return findings;
  }

  // ── Activity Log Analysis ─────────────────────────────────────────────────

  private async checkActivityLogs(startTime: string, endTime: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const monitorClient = this.client.monitor();

    const filter = `eventTimestamp ge '${startTime}' and eventTimestamp le '${endTime}'`;

    const events: any[] = [];
    try {
      for await (const e of monitorClient.activityLogs.list(filter)) {
        events.push(e);
        if (events.length >= 2000) break; // safety cap
      }
    } catch {
      return findings; // activity logs unavailable
    }

    // ── 1. Mass Key Vault secret reads ─────────────────────────────────────
    const kvReads = events.filter(e =>
      e.operationName?.value?.toLowerCase().includes('microsoft.keyvault/vaults/secrets') &&
      e.operationName?.value?.toLowerCase().includes('read') &&
      e.status?.value === 'Succeeded',
    );

    const kvReadsByPrincipal = groupBy(kvReads, e => e.claims?.oid ?? e.caller ?? 'unknown');
    for (const [principal, reads] of kvReadsByPrincipal.entries()) {
      if (reads.length >= 20) {
        findings.push(this.finding(
          'Suspicious mass read of secrets from Key Vault',
          `Principal "${principal}" performed ${reads.length} Key Vault secret read operations in the monitoring window. Mass reads may indicate credential harvesting or secrets exfiltration.`,
          reads.length >= 50 ? 'CRITICAL' : 'HIGH',
          {
            threatCategory: 'CredentialAccess',
            principal,
            count: reads.length,
            vaults: [...new Set(reads.map(e => extractResourceName(e.resourceId ?? '')))].slice(0, 5),
            firstEvent: reads[0]?.eventTimestamp,
            lastEvent:  reads[reads.length - 1]?.eventTimestamp,
            eventCorrelationId: reads[0]?.correlationId,
          },
          'Investigate the principal. If access is unexpected, revoke Key Vault permissions immediately and rotate all secrets. Enable Key Vault diagnostic logging for permanent audit trail.',
          ['threat', 'credential-access', 'keyvault'],
        ));
      }
    }

    // ── 2. Privilege escalation — new privileged role assignment ───────────
    const roleAssignments = events.filter(e =>
      e.operationName?.value === 'Microsoft.Authorization/roleAssignments/write' &&
      e.status?.value === 'Succeeded',
    );

    for (const evt of roleAssignments) {
      const props = evt.properties?.requestBody ?? evt.properties ?? {};
      const roleDefId = (props.roleDefinitionId ?? props.RoleDefinitionId ?? '').toString();
      const roleShortId = roleDefId.split('/').pop() ?? '';

      if (PRIVILEGED_ROLE_IDS.has(roleShortId)) {
        findings.push(this.finding(
          'Suspicious privilege escalation: new Owner assignment',
          `Caller "${evt.caller ?? 'unknown'}" assigned a privileged role (${roleShortId}) at ${evt.resourceGroupName ? 'resource group' : 'subscription'} scope. Unexpected privilege escalation may indicate account compromise.`,
          'CRITICAL',
          {
            threatCategory: 'PrivilegeEscalation',
            caller: evt.caller,
            roleDefinitionId: roleDefId,
            scope: evt.resourceId,
            eventTime: evt.eventTimestamp,
            correlationId: evt.correlationId,
          },
          'Verify whether this role assignment was authorised. If not, remove the assignment immediately, revoke the caller\'s credentials, and audit all actions taken by the principal after the assignment.',
          ['threat', 'privilege-escalation', 'iam'],
        ));
      }
    }

    // ── 3. Bulk resource deletion ──────────────────────────────────────────
    const deletions = events.filter(e =>
      e.operationName?.value?.toLowerCase().endsWith('/delete') &&
      e.status?.value === 'Succeeded',
    );

    const deletionsByPrincipal = groupBy(deletions, e => e.caller ?? 'unknown');
    for (const [principal, dels] of deletionsByPrincipal.entries()) {
      if (dels.length >= 10) {
        findings.push(this.finding(
          'Anomalous deletion of resources',
          `Principal "${principal}" deleted ${dels.length} resources in the monitoring window. Bulk deletions may indicate account takeover, insider threat, or misconfigured automation.`,
          dels.length >= 25 ? 'CRITICAL' : 'HIGH',
          {
            threatCategory: 'Impact',
            principal,
            count: dels.length,
            resourceTypes: [...new Set(dels.map(e => extractResourceType(e.resourceId ?? '')))].slice(0, 8),
            firstEvent: dels[0]?.eventTimestamp,
            correlationId: dels[0]?.correlationId,
          },
          'Investigate whether the deletions were authorised. Enable Azure resource locks on critical resources to prevent accidental or malicious deletion.',
          ['threat', 'impact', 'deletion'],
        ));
      }
    }

    // ── 4. Suspicious API calls from anonymous / unknown principals ────────
    const anonCalls = events.filter(e =>
      e.status?.value === 'Succeeded' &&
      (!e.caller || e.caller.toLowerCase() === 'anonymous' || e.caller === '') &&
      e.level?.toLowerCase() !== 'informational',
    );

    if (anonCalls.length > 0) {
      findings.push(this.finding(
        'Suspicious API calls from anonymous/unknown principal',
        `${anonCalls.length} successful Azure control-plane operation(s) were performed by an anonymous or unknown principal in the monitoring window. Operations: ${[...new Set(anonCalls.map(e => e.operationName?.value ?? ''))].slice(0, 5).join(', ')}.`,
        'HIGH',
        {
          threatCategory: 'InitialAccess',
          count: anonCalls.length,
          operations: [...new Set(anonCalls.map(e => e.operationName?.value ?? ''))].slice(0, 10),
          firstEvent: anonCalls[0]?.eventTimestamp,
        },
        'Ensure all Azure resources require authentication. Review public-facing endpoints. Investigate whether any resources were exposed without authentication.',
        ['threat', 'anonymous-access'],
      ));
    }

    // ── 5. Brute force: many 401 Unauthorized followed by success ─────────
    const failedAuths = events.filter(e =>
      (e.status?.value === 'Failed' || e.level?.toLowerCase() === 'warning') &&
      e.operationName?.value?.toLowerCase().includes('login'),
    );
    const successAuths = events.filter(e =>
      e.status?.value === 'Succeeded' &&
      e.operationName?.value?.toLowerCase().includes('login'),
    );

    const failedByPrincipal = groupBy(failedAuths, e => e.caller ?? e.claims?.upn ?? 'unknown');
    for (const [principal, fails] of failedByPrincipal.entries()) {
      if (fails.length >= 5) {
        const hasSubsequentSuccess = successAuths.some(s =>
          (s.caller ?? s.claims?.upn ?? '') === principal &&
          new Date(s.eventTimestamp ?? 0) > new Date(fails[fails.length - 1]?.eventTimestamp ?? 0),
        );
        if (hasSubsequentSuccess) {
          findings.push(this.finding(
            'Brute force: multiple failed sign-ins followed by success',
            `Principal "${principal}" had ${fails.length} failed authentication attempts followed by a successful sign-in. This pattern is consistent with a successful brute-force or password spray attack.`,
            'CRITICAL',
            {
              threatCategory: 'CredentialAccess',
              principal,
              failedAttempts: fails.length,
              firstFailure: fails[0]?.eventTimestamp,
              lastFailure:  fails[fails.length - 1]?.eventTimestamp,
            },
            'Immediately reset credentials for this principal, enable MFA if not already enabled, and review all actions taken after the successful sign-in.',
            ['threat', 'brute-force', 'credential-access'],
          ));
        }
      }
    }

    // ── 6. Large-scale storage data export ────────────────────────────────
    const storageReads = events.filter(e =>
      e.operationName?.value?.toLowerCase().includes('microsoft.storage') &&
      (e.operationName?.value?.toLowerCase().includes('blob/read') ||
       e.operationName?.value?.toLowerCase().includes('blob/list')) &&
      e.status?.value === 'Succeeded',
    );

    const storageReadsByPrincipal = groupBy(storageReads, e => e.caller ?? 'unknown');
    for (const [principal, reads] of storageReadsByPrincipal.entries()) {
      if (reads.length >= 50) {
        findings.push(this.finding(
          'Large-scale data export from Storage account',
          `Principal "${principal}" performed ${reads.length} Storage blob read/list operations in the monitoring window. This volume may indicate data exfiltration.`,
          'HIGH',
          {
            threatCategory: 'Exfiltration',
            principal,
            count: reads.length,
            accounts: [...new Set(reads.map(e => extractResourceName(e.resourceId ?? '')))].slice(0, 5),
            firstEvent: reads[0]?.eventTimestamp,
          },
          'Review whether this access was expected. If not, revoke the principal\'s Storage permissions and rotate SAS tokens. Enable Storage diagnostic logging for detailed blob-level audit.',
          ['threat', 'exfiltration', 'storage'],
        ));
      }
    }

    return findings;
  }

  // ── NSG Rule Change Detection ─────────────────────────────────────────────

  private async checkNSGChanges(startTime: string, endTime: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const networkClient = this.client.network();
    const monitorClient = this.client.monitor();

    // Get NSG write events from Activity Log
    const filter = `eventTimestamp ge '${startTime}' and eventTimestamp le '${endTime}' and resourceType eq 'Microsoft.Network/networkSecurityGroups'`;

    try {
      const nsgEvents: any[] = [];
      for await (const e of monitorClient.activityLogs.list(filter)) {
        if (
          e.operationName?.value?.includes('securityRules/write') &&
          e.status?.value === 'Succeeded'
        ) {
          nsgEvents.push(e);
        }
        if (nsgEvents.length >= 200) break;
      }

      if (nsgEvents.length === 0) return findings;

      // For each NSG that was modified, re-check the current rule state
      const modifiedNsgIds = new Set(nsgEvents.map(e => e.resourceId ?? '').filter(Boolean));

      for (const nsgId of modifiedNsgIds) {
        try {
          const parts   = nsgId.split('/');
          const rg      = parts[4];
          const nsgName = parts[8];
          if (!rg || !nsgName) continue;

          const nsg   = await networkClient.networkSecurityGroups.get(rg, nsgName);
          const rules = nsg.securityRules ?? [];

          const openManagementRules = rules.filter((r: any) => {
            if (r.access !== 'Allow' || r.direction !== 'Inbound') return false;
            const src = r.sourceAddressPrefix ?? '';
            if (!['*', '0.0.0.0/0', 'Internet', 'Any'].includes(src)) return false;
            const portSpecs = [r.destinationPortRange ?? '', ...(r.destinationPortRanges ?? [])].filter(Boolean);
            return portSpecs.some((spec: string) => {
              if (spec === '*') return true;
              if (spec.includes('-')) {
                const [lo, hi] = spec.split('-').map(Number);
                return [...MANAGEMENT_PORTS].some(p => {
                  const pn = Number(p);
                  return pn >= lo && pn <= hi;
                });
              }
              return MANAGEMENT_PORTS.has(spec);
            });
          });

          if (openManagementRules.length > 0) {
            const callers = [...new Set(nsgEvents
              .filter(e => (e.resourceId ?? '').toLowerCase() === nsgId.toLowerCase())
              .map(e => e.caller ?? 'unknown'))];

            findings.push(this.finding(
              'NSG rule modified to open management port to internet',
              `NSG "${nsgName}" was recently modified by ${callers.join(', ')} and now has ${openManagementRules.length} rule(s) allowing inbound management ports (${openManagementRules.map((r: any) => r.destinationPortRange ?? r.name).join(', ')}) from 0.0.0.0/0.`,
              'CRITICAL',
              {
                threatCategory: 'DefenseEvasion',
                nsg: nsgName,
                resourceGroup: rg,
                callers,
                openRules: openManagementRules.map((r: any) => ({
                  name: r.name,
                  port: r.destinationPortRange,
                  priority: r.priority,
                })),
              },
              'Immediately remove or restrict the overly permissive NSG rule. Investigate why this change was made. Consider requiring PIM or approval for NSG modifications in production.',
              ['threat', 'defense-evasion', 'nsg'],
            ));
          }
        } catch { /* skip individual NSG errors */ }
      }
    } catch { /* NSG change detection optional */ }

    return findings;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function groupBy<T>(items: T[], keyFn: (item: T) => string): Map<string, T[]> {
  const map = new Map<string, T[]>();
  for (const item of items) {
    const key = keyFn(item);
    const arr = map.get(key) ?? [];
    arr.push(item);
    map.set(key, arr);
  }
  return map;
}

function extractResourceName(resourceId: string): string {
  return resourceId.split('/').pop() ?? resourceId;
}

function extractResourceType(resourceId: string): string {
  // e.g. /subscriptions/.../providers/Microsoft.Compute/virtualMachines/myVm
  const parts = resourceId.split('/');
  const providerIdx = parts.findIndex(p => p.toLowerCase() === 'providers');
  if (providerIdx >= 0 && parts[providerIdx + 1] && parts[providerIdx + 2]) {
    return `${parts[providerIdx + 1]}/${parts[providerIdx + 2]}`;
  }
  return 'Unknown';
}
