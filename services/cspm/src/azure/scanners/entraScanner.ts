/**
 * Azure Entra ID (Azure AD) Scanner
 *
 * Calls Microsoft Graph REST API directly using the service principal credential.
 * Required API permissions (application):
 *   - Policy.Read.All         — Conditional Access policies
 *   - Directory.Read.All      — Users, groups, service principals, directory roles
 *   - RoleManagement.Read.All — PIM role assignments (optional, graceful fallback)
 *
 * All checks degrade gracefully if the permission is missing (returns INFO finding).
 */

import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const GRAPH_BASE = 'https://graph.microsoft.com/v1.0';

// Built-in privileged directory role template IDs
const PRIVILEGED_DIR_ROLES = new Map([
  ['62e90394-69f5-4237-9190-012177145e10', 'Global Administrator'],
  ['e8611ab8-c189-46e8-94e1-60213ab1f814', 'Privileged Role Administrator'],
  ['194ae4cb-b126-40b2-bd5b-6091b380977d', 'Security Administrator'],
  ['9360feb5-f418-4baa-8175-e2a00bac4301', 'Directory Writers'],
  ['29232cdf-9323-42fd-ade2-1d097af3e4de', 'Exchange Administrator'],
  ['f28a1f50-f6e7-4571-818b-6a12f2af6b6c', 'SharePoint Administrator'],
  ['fe930be7-5e62-47db-91af-98c3a49a38b1', 'User Administrator'],
  ['9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', 'Application Administrator'],
  ['c4e39bd9-1100-46d3-8c65-fb160da0071f', 'Authentication Administrator'],
]);

export class AzureEntraScanner extends AzureBaseScanner {
  private graphToken: string | null = null;

  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-Entra');
  }

  private async getGraphToken(): Promise<string | null> {
    if (this.graphToken) return this.graphToken;
    try {
      const tokenResponse = await this.client.credential.getToken(
        'https://graph.microsoft.com/.default',
      );
      this.graphToken = tokenResponse?.token ?? null;
      return this.graphToken;
    } catch {
      return null;
    }
  }

  private async graphGet(path: string): Promise<any> {
    const token = await this.getGraphToken();
    if (!token) throw new Error('Unable to obtain Microsoft Graph token — check API permissions');

    const res = await fetch(`${GRAPH_BASE}${path}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`Graph API ${path} returned ${res.status}: ${body.slice(0, 200)}`);
    }

    return res.json();
  }

  /** Paginate through all pages of a Graph API list */
  private async graphGetAll(path: string): Promise<any[]> {
    const results: any[] = [];
    let url: string | null = `${GRAPH_BASE}${path}`;
    const token = await this.getGraphToken();
    if (!token) throw new Error('Unable to obtain Microsoft Graph token');

    while (url) {
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      });
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(`Graph API returned ${res.status}: ${body.slice(0, 200)}`);
      }
      const data: any = await res.json();
      results.push(...(data.value ?? []));
      url = data['@odata.nextLink'] ?? null;
      if (results.length >= 500) break; // safety cap
    }
    return results;
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    // Verify Graph token is obtainable before running checks
    const token = await this.getGraphToken();
    if (!token) {
      findings.push(this.finding(
        'Azure Entra ID scan skipped — Graph API permissions missing',
        'The service principal could not obtain a Microsoft Graph token. Entra ID security checks (MFA, legacy auth, CA policies, directory roles) were not performed.',
        'INFO',
        { reason: 'no_graph_token' },
        'Grant the service principal Policy.Read.All and Directory.Read.All application permissions on Microsoft Graph, then re-run the scan.',
        ['entra', 'permissions'],
      ));
      return findings;
    }

    const [caResults, roleResults, userResults, spResults] = await Promise.allSettled([
      this.checkConditionalAccess(),
      this.checkPrivilegedDirectoryRoles(),
      this.checkGuestUsers(),
      this.checkServicePrincipals(),
    ]);

    if (caResults.status === 'fulfilled')   findings.push(...caResults.value);
    else findings.push(this.finding('Entra Conditional Access check failed', caResults.reason?.message ?? 'Unknown error', 'INFO', { error: caResults.reason?.message }, 'Ensure Policy.Read.All permission is granted on Microsoft Graph.', ['entra']));

    if (roleResults.status === 'fulfilled') findings.push(...roleResults.value);
    else findings.push(this.finding('Entra directory role check failed', roleResults.reason?.message ?? 'Unknown error', 'INFO', { error: roleResults.reason?.message }, 'Ensure Directory.Read.All permission is granted on Microsoft Graph.', ['entra']));

    if (userResults.status === 'fulfilled') findings.push(...userResults.value);
    else findings.push(this.finding('Entra user check failed', userResults.reason?.message ?? 'Unknown error', 'INFO', { error: userResults.reason?.message }, 'Ensure Directory.Read.All permission is granted on Microsoft Graph.', ['entra']));

    if (spResults.status === 'fulfilled')   findings.push(...spResults.value);

    return findings;
  }

  // ── Conditional Access Policies ──────────────────────────────────────────

  private async checkConditionalAccess(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const data = await this.graphGet('/identity/conditionalAccess/policies');
    const policies: any[] = data.value ?? [];

    const enabledPolicies = policies.filter(p => p.state === 'enabled');

    // 1. MFA enforcement — look for a CA policy requiring MFA for all users
    const mfaPolicy = enabledPolicies.find(p => {
      const conditions  = p.conditions ?? {};
      const grantCtrl   = p.grantControls ?? {};
      const builtInCtrl: string[] = grantCtrl.builtInControls ?? [];

      // Must require MFA
      if (!builtInCtrl.includes('mfa')) return false;

      // Must target all users (or a broad group)
      const users = conditions.users ?? {};
      const includeUsers  = users.includeUsers  ?? [];
      const includeGroups = users.includeGroups ?? [];
      return includeUsers.includes('All') || includeGroups.length > 0;
    });

    if (!mfaPolicy) {
      findings.push(this.emit(
        'entra_conditional_access_mfa_all_users',
        { totalPolicies: policies.length, enabledPolicies: enabledPolicies.length },
        { message: `No enabled Conditional Access policy was found that requires MFA for all (or a broad set of) users. Users can authenticate to Azure AD with only a password, making accounts vulnerable to password spray and credential stuffing attacks.` },
      ));
    }

    // 2. Legacy authentication — no policy blocking legacy auth protocols
    const legacyAuthBlockPolicy = enabledPolicies.find(p => {
      const conditions = p.conditions ?? {};
      const grantCtrl  = p.grantControls ?? {};
      const builtIn: string[] = grantCtrl.builtInControls ?? [];

      // Block control + legacy auth client apps condition
      if (!builtIn.includes('block')) return false;
      const clientApps: string[] = conditions.clientAppTypes ?? [];
      return (
        clientApps.includes('exchangeActiveSync') ||
        clientApps.includes('other') ||
        clientApps.some((c: string) => c.toLowerCase().includes('legacy'))
      );
    });

    if (!legacyAuthBlockPolicy) {
      findings.push(this.emit(
        'entra_conditional_access_legacy_auth_blocked',
        { enabledPolicies: enabledPolicies.length },
        { message: 'No enabled Conditional Access policy was found that blocks legacy authentication protocols (Basic Auth, SMTP AUTH, IMAP, POP, older Office clients). Legacy auth bypasses MFA and is the vector for over 99% of password spray attacks on Azure AD.' },
      ));
    }

    // 3. No policies at all (or only report-only)
    if (policies.length === 0) {
      findings.push(this.emit(
        'entra_conditional_access_policies_exist',
        {},
        { message: 'The tenant has no Conditional Access policies defined. All authentication relies solely on password strength with no risk-based or MFA requirements.' },
      ));
    } else if (enabledPolicies.length === 0) {
      findings.push(this.emit(
        'entra_conditional_access_not_report_only',
        { totalPolicies: policies.length },
        { message: `${policies.length} Conditional Access policy/policies exist but all are in report-only mode. No access controls are being enforced.` },
      ));
    }

    return findings;
  }

  // ── Privileged Directory Roles ────────────────────────────────────────────

  private async checkPrivilegedDirectoryRoles(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    // List all active directory role assignments
    const assignments = await this.graphGetAll(
      '/roleManagement/directory/roleAssignments?$expand=principal',
    );

    // Group by role definition ID
    const byRole = new Map<string, any[]>();
    for (const assignment of assignments) {
      const roleId = assignment.roleDefinitionId ?? '';
      if (!byRole.has(roleId)) byRole.set(roleId, []);
      byRole.get(roleId)!.push(assignment);
    }

    // 1. Global Administrator count
    const globalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10';
    const globalAdmins = byRole.get(globalAdminRoleId) ?? [];
    if (globalAdmins.length > 5) {
      findings.push(this.emit(
        'entra_directory_role_global_admin_count_bounded',
        {
          count: globalAdmins.length,
          principals: globalAdmins.slice(0, 10).map(a => a.principal?.userPrincipalName ?? a.principal?.displayName ?? a.principalId),
        },
        { message: `${globalAdmins.length} principals are assigned the Global Administrator role. Microsoft recommends no more than 2–4 break-glass accounts plus PIM-eligible assignments. Permanent Global Admin assignments significantly increase compromise risk.` },
      ));
    } else if (globalAdmins.length === 0) {
      findings.push(this.emit(
        'entra_directory_role_global_admin_breakglass_configured',
        {},
        { message: 'No principals are permanently assigned the Global Administrator role. While over-assignment is a risk, having zero permanent Global Admins may indicate break-glass accounts are not properly configured.' },
      ));
    }

    // 2. Check each privileged role for excessive assignment
    for (const [templateId, roleName] of PRIVILEGED_DIR_ROLES.entries()) {
      const assignees = byRole.get(templateId) ?? [];
      if (assignees.length > 10) {
        findings.push(this.emit(
          'entra_directory_role_assignment_count_bounded',
          {
            role: roleName,
            count: assignees.length,
            principals: assignees.slice(0, 5).map(a => a.principal?.userPrincipalName ?? a.principalId),
          },
          { message: `${assignees.length} principals are permanently assigned the "${roleName}" directory role. Large numbers of permanent privileged role assignments increase the blast radius of an account compromise.` },
        ));
      }
    }

    // 3. Guest users in privileged roles
    const guestPrivileged = assignments.filter(a => {
      const roleId = a.roleDefinitionId ?? '';
      return PRIVILEGED_DIR_ROLES.has(roleId) &&
        (a.principal?.userType === 'Guest' || (a.principal?.userPrincipalName ?? '').includes('#EXT#'));
    });

    if (guestPrivileged.length > 0) {
      findings.push(this.emit(
        'entra_directory_role_no_guest_assignees',
        { count: guestPrivileged.length, principals: guestPrivileged.slice(0, 10).map(a => a.principal?.userPrincipalName ?? a.principalId) },
        { message: `${guestPrivileged.length} guest/external user(s) are assigned privileged Azure AD directory roles: ${guestPrivileged.slice(0, 5).map(a => a.principal?.userPrincipalName ?? a.principalId).join(', ')}.` },
      ));
    }

    return findings;
  }

  // ── Guest User Hygiene ────────────────────────────────────────────────────

  private async checkGuestUsers(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const guests = await this.graphGetAll(
        '/users?$filter=userType eq \'Guest\'&$select=id,displayName,userPrincipalName,signInActivity,createdDateTime',
      );

      const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);

      // Guests with no sign-in in 90 days
      const staleGuests = guests.filter(g => {
        const lastSignIn = g.signInActivity?.lastSignInDateTime;
        if (!lastSignIn) return true; // never signed in
        return new Date(lastSignIn) < ninetyDaysAgo;
      });

      if (staleGuests.length > 0) {
        findings.push(this.emit(
          'entra_guest_user_recent_signin',
          {
            count: staleGuests.length,
            guests: staleGuests.slice(0, 10).map(g => ({
              upn: g.userPrincipalName,
              lastSignIn: g.signInActivity?.lastSignInDateTime ?? 'never',
            })),
          },
          { message: `${staleGuests.length} guest user(s) have not signed in for over 90 days or have never signed in. Stale guest accounts increase the attack surface and may retain access to shared resources.` },
        ));
      }

      // Large number of guests
      if (guests.length > 50) {
        findings.push(this.emit(
          'entra_guest_user_population_bounded',
          { guestCount: guests.length },
          { message: `The tenant has ${guests.length} guest users. A large guest population increases the risk of forgotten, over-privileged, or compromised external accounts.` },
        ));
      }
    } catch { /* signInActivity may require AAD Premium P2 — skip gracefully */ }

    return findings;
  }

  // ── Service Principal Hygiene ─────────────────────────────────────────────

  private async checkServicePrincipals(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const sps = await this.graphGetAll(
        '/servicePrincipals?$select=id,displayName,appId,signInAudience,keyCredentials,passwordCredentials,createdDateTime',
      );

      const now = new Date();

      // 1. Service principals with expiring credentials in < 30 days
      const expiringCreds: any[] = [];
      const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

      for (const sp of sps) {
        const allCreds = [
          ...(sp.keyCredentials      ?? []),
          ...(sp.passwordCredentials ?? []),
        ];
        for (const cred of allCreds) {
          if (!cred.endDateTime) continue;
          const expiry = new Date(cred.endDateTime);
          if (expiry < thirtyDaysFromNow && expiry > now) {
            expiringCreds.push({ sp: sp.displayName, expiry: cred.endDateTime });
          }
        }
      }

      if (expiringCreds.length > 0) {
        findings.push(this.emit(
          'entra_service_principal_credential_not_expiring',
          { count: expiringCreds.length, credentials: expiringCreds.slice(0, 10) },
          { message: `${expiringCreds.length} service principal credential(s) expire within 30 days: ${expiringCreds.slice(0, 5).map(c => `${c.sp} (${c.expiry})`).join(', ')}. Expired credentials cause application outages.` },
        ));
      }

      // 2. Service principals with already-expired credentials
      const expiredCreds: any[] = [];
      for (const sp of sps) {
        const allCreds = [
          ...(sp.keyCredentials      ?? []),
          ...(sp.passwordCredentials ?? []),
        ];
        for (const cred of allCreds) {
          if (!cred.endDateTime) continue;
          if (new Date(cred.endDateTime) < now) {
            expiredCreds.push({ sp: sp.displayName, expiry: cred.endDateTime });
          }
        }
      }

      if (expiredCreds.length > 0) {
        findings.push(this.emit(
          'entra_service_principal_credential_not_expired',
          { count: expiredCreds.length, credentials: expiredCreds.slice(0, 10) },
          { message: `${expiredCreds.length} service principal credential(s) are already expired. These applications are broken and may be abandoned but still hold role assignments.` },
        ));
      }

      // 3. Multi-tenant service principals (signInAudience = AzureADMultipleOrgs or All)
      const multiTenantSPs = sps.filter(sp =>
        sp.signInAudience === 'AzureADMultipleOrgs' ||
        sp.signInAudience === 'AzureADandPersonalMicrosoftAccount',
      );

      if (multiTenantSPs.length > 0) {
        findings.push(this.emit(
          'entra_service_principal_not_multitenant',
          { count: multiTenantSPs.length, servicePrincipals: multiTenantSPs.slice(0, 10).map(sp => sp.displayName) },
          { message: `${multiTenantSPs.length} service principal(s) are registered as multi-tenant applications: ${multiTenantSPs.slice(0, 5).map(sp => sp.displayName).join(', ')}. Multi-tenant apps can be consented to and used from any Azure AD tenant, expanding the attack surface.` },
        ));
      }
    } catch { /* SP checks optional */ }

    return findings;
  }
}
