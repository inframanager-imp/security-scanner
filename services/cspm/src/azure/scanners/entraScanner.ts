// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
/**
 * Azure Entra ID (Azure AD) Scanner
 *
 * Calls Microsoft Graph REST API directly using the service principal credential.
 * Required API permissions (application):
 *   - Policy.Read.All             — Conditional Access policies, authorization policy, named locations
 *   - Directory.Read.All          — Users, groups, service principals, directory roles, group settings
 *   - RoleManagement.Read.All     — PIM/directory role assignments (optional, graceful fallback)
 *   - Application.Read.All        — App registrations and their credentials
 *   - Policy.Read.All (auth methods) — Authentication methods policy
 *
 * Also uses the ARM Authorization client (this.client.authorization()) for
 * entra_user_with_vm_access_has_mfa, which cross-references Azure RBAC role
 * assignments against Entra users — this is the one check in this scanner
 * that spans both Graph and ARM.
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

const GLOBAL_ADMIN_ROLE_ID = '62e90394-69f5-4237-9190-012177145e10';

// Azure config constants (Prowler providers/azure/config.py)
const MICROSOFT_ADMIN_PORTALS = 'MicrosoftAdminPortals';
const WINDOWS_AZURE_SERVICE_MANAGEMENT_API = '797f4846-ba00-4fd7-ba43-dac1f8f63013';
const GUEST_USER_ACCESS_RESTRICTED = '2af84b1e-32c8-42b7-82bc-daa82404023b';
const STRONG_AUTH_METHODS = new Set(['microsoftAuthenticator', 'fido2', 'x509Certificate']);
const VM_ACCESS_ROLE_IDS = new Map([
  ['8e3af657-a8ff-443c-a75c-2fe8c4bcb635', 'Owner'],
  ['b24988ac-6180-42a0-ab88-20f7382dd24c', 'Contributor'],
  ['9980e02c-c2be-4d73-94e8-173b1dc7cf3c', 'Virtual Machine Contributor'],
  ['1c0163c0-47e6-4577-8991-ea5c82e286e4', 'Virtual Machine Administrator Login'],
  ['fb879df8-f326-4884-b1cf-06f3ad86be52', 'Virtual Machine User Login'],
  ['602da2ba-a5c2-41da-b01d-5360126ab525', 'Virtual Machine Local User Login'],
  ['4229625d-573c-4f4f-8371-8ad9a4bd50b6', 'Windows Admin Center Administrator Login'],
]);
const APP_REGISTRATION_CRED_EXPIRY_WARNING_DAYS = 30;
const STALE_USER_SIGNIN_THRESHOLD_DAYS = 90;

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

    const [
      caResults,
      roleResults,
      userResults,
      spResults,
      authPolicyResults,
      securityDefaultsResults,
      namedLocationsResults,
      groupSettingsResults,
      appRegResults,
      authMethodsResults,
      vmAccessMfaResults,
      userMfaSignInResults,
    ] = await Promise.allSettled([
      this.checkConditionalAccess(),
      this.checkPrivilegedDirectoryRoles(),
      this.checkGuestUsers(),
      this.checkServicePrincipals(),
      this.checkAuthorizationPolicy(),
      this.checkSecurityDefaults(),
      this.checkTrustedNamedLocations(),
      this.checkGroupCreationSettings(),
      this.checkAppRegistrationCredentials(),
      this.checkAuthenticationMethodsPolicy(),
      this.checkUserVmAccessMfa(),
      this.checkUserMfaAndSignIn(),
    ]);

    if (caResults.status === 'fulfilled')   findings.push(...caResults.value);
    else findings.push(this.finding('Entra Conditional Access check failed', caResults.reason?.message ?? 'Unknown error', 'INFO', { error: caResults.reason?.message }, 'Ensure Policy.Read.All permission is granted on Microsoft Graph.', ['entra']));

    if (roleResults.status === 'fulfilled') findings.push(...roleResults.value);
    else findings.push(this.finding('Entra directory role check failed', roleResults.reason?.message ?? 'Unknown error', 'INFO', { error: roleResults.reason?.message }, 'Ensure Directory.Read.All permission is granted on Microsoft Graph.', ['entra']));

    if (userResults.status === 'fulfilled') findings.push(...userResults.value);
    else findings.push(this.finding('Entra user check failed', userResults.reason?.message ?? 'Unknown error', 'INFO', { error: userResults.reason?.message }, 'Ensure Directory.Read.All permission is granted on Microsoft Graph.', ['entra']));

    if (spResults.status === 'fulfilled')   findings.push(...spResults.value);

    if (authPolicyResults.status === 'fulfilled') findings.push(...authPolicyResults.value);
    else findings.push(this.finding('Entra authorization policy check failed', authPolicyResults.reason?.message ?? 'Unknown error', 'INFO', { error: authPolicyResults.reason?.message }, 'Ensure Policy.Read.All permission is granted on Microsoft Graph.', ['entra']));

    if (securityDefaultsResults.status === 'fulfilled') findings.push(...securityDefaultsResults.value);
    else findings.push(this.finding('Entra security defaults check failed', securityDefaultsResults.reason?.message ?? 'Unknown error', 'INFO', { error: securityDefaultsResults.reason?.message }, 'Ensure Policy.Read.All permission is granted on Microsoft Graph.', ['entra']));

    if (namedLocationsResults.status === 'fulfilled') findings.push(...namedLocationsResults.value);
    else findings.push(this.finding('Entra named locations check failed', namedLocationsResults.reason?.message ?? 'Unknown error', 'INFO', { error: namedLocationsResults.reason?.message }, 'Ensure Policy.Read.All permission is granted on Microsoft Graph.', ['entra']));

    if (groupSettingsResults.status === 'fulfilled') findings.push(...groupSettingsResults.value);
    else findings.push(this.finding('Entra group settings check failed', groupSettingsResults.reason?.message ?? 'Unknown error', 'INFO', { error: groupSettingsResults.reason?.message }, 'Ensure Directory.Read.All permission is granted on Microsoft Graph.', ['entra']));

    if (appRegResults.status === 'fulfilled') findings.push(...appRegResults.value);
    else findings.push(this.finding('Entra app registration check failed', appRegResults.reason?.message ?? 'Unknown error', 'INFO', { error: appRegResults.reason?.message }, 'Ensure Application.Read.All permission is granted on Microsoft Graph.', ['entra']));

    if (authMethodsResults.status === 'fulfilled') findings.push(...authMethodsResults.value);
    else findings.push(this.finding('Entra authentication methods policy check failed', authMethodsResults.reason?.message ?? 'Unknown error', 'INFO', { error: authMethodsResults.reason?.message }, 'Ensure Policy.Read.All permission is granted on Microsoft Graph.', ['entra']));

    if (vmAccessMfaResults.status === 'fulfilled') findings.push(...vmAccessMfaResults.value);
    // vmAccessMfa is optional — requires ARM Authorization permissions in addition to Graph; skip silently on failure

    if (userMfaSignInResults.status === 'fulfilled') findings.push(...userMfaSignInResults.value);
    else findings.push(this.finding('Entra user MFA/sign-in check failed', userMfaSignInResults.reason?.message ?? 'Unknown error', 'INFO', { error: userMfaSignInResults.reason?.message }, 'Ensure Directory.Read.All and UserAuthenticationMethod.Read.All permissions are granted on Microsoft Graph.', ['entra']));

    return findings;
  }

  // ── Conditional Access Policies ──────────────────────────────────────────

  private async checkConditionalAccess(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const data = await this.graphGet('/identity/conditionalAccess/policies');
    const policies: any[] = data.value ?? [];

    const enabledPolicies = policies.filter(p => p.state === 'enabled');

    // entra_conditional_access_mfa_all_users: MFA enforcement — look for a CA
    // policy requiring MFA for all users
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
        { message: 'No enabled Conditional Access policy was found that requires MFA for all (or a broad set of) users. Users can authenticate to Azure AD with only a password, making accounts vulnerable to password spray and credential stuffing attacks.' },
      ));
    }

    // entra_conditional_access_legacy_auth_blocked: no policy blocking legacy auth protocols
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

    // entra_conditional_access_policies_exist / entra_conditional_access_not_report_only
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

    // entra_conditional_access_policy_require_mfa_for_admin_portals
    const adminPortalsMfaPolicy = enabledPolicies.find(p => {
      const conditions = p.conditions ?? {};
      const users = conditions.users ?? {};
      const includeUsers: string[] = users.includeUsers ?? [];
      const targetResources = conditions.applications ?? {};
      const includeApps: string[] = targetResources.includeApplications ?? [];
      const grantCtrl = p.grantControls ?? {};
      const builtIn: string[] = grantCtrl.builtInControls ?? [];
      return includeUsers.includes('All') &&
        includeApps.includes(MICROSOFT_ADMIN_PORTALS) &&
        builtIn.some((c: string) => c.toLowerCase().includes('mfa'));
    });

    if (adminPortalsMfaPolicy) {
      // PASS case is implicit — no finding emitted for passing checks in this scanner's convention.
    } else {
      findings.push(this.emit(
        'entra_conditional_access_policy_require_mfa_for_admin_portals',
        { enabledPolicies: enabledPolicies.length },
        { message: 'No enabled Conditional Access policy requires MFA for the Microsoft Admin Portals app across all users.' },
      ));
    }

    // entra_conditional_access_policy_require_mfa_for_management_api
    const mgmtApiMfaPolicy = enabledPolicies.find(p => {
      const conditions = p.conditions ?? {};
      const users = conditions.users ?? {};
      const includeUsers: string[] = users.includeUsers ?? [];
      const targetResources = conditions.applications ?? {};
      const includeApps: string[] = targetResources.includeApplications ?? [];
      const grantCtrl = p.grantControls ?? {};
      const builtIn: string[] = grantCtrl.builtInControls ?? [];
      return includeUsers.includes('All') &&
        includeApps.includes(WINDOWS_AZURE_SERVICE_MANAGEMENT_API) &&
        builtIn.some((c: string) => c.toLowerCase().includes('mfa'));
    });

    if (!mgmtApiMfaPolicy) {
      findings.push(this.emit(
        'entra_conditional_access_policy_require_mfa_for_management_api',
        { enabledPolicies: enabledPolicies.length },
        { message: 'No enabled Conditional Access policy requires MFA for the Windows Azure Service Management API (Azure CLI, PowerShell, ARM) across all users.' },
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

    // entra_directory_role_global_admin_count_bounded / breakglass_configured
    const globalAdmins = byRole.get(GLOBAL_ADMIN_ROLE_ID) ?? [];
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

    // entra_global_admin_in_less_than_five_users (Prowler-verbatim: threshold is >=5, distinct
    // checkId from the one above even though the underlying signal is related)
    if (globalAdmins.length >= 5) {
      findings.push(this.emit(
        'entra_global_admin_in_less_than_five_users',
        { count: globalAdmins.length },
        { message: `There are ${globalAdmins.length} global administrators. It should be less than five.` },
      ));
    }

    // entra_directory_role_assignment_count_bounded: check each privileged role for excessive assignment
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
          {
            message: `${assignees.length} principals are permanently assigned the "${roleName}" directory role. Large numbers of permanent privileged role assignments increase the blast radius of an account compromise.`,
            remediation: `Use Azure AD PIM to convert permanent "${roleName}" assignments to eligible assignments requiring activation. Review and remove stale assignments.`,
          },
        ));
      }
    }

    // entra_directory_role_no_guest_assignees
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

      // entra_guest_user_recent_signin: guests with no sign-in in 90 days
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

      // entra_guest_user_population_bounded: large number of guests
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

      // entra_service_principal_credential_not_expiring: creds expiring < 30 days
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

      // entra_service_principal_credential_not_expired: already-expired credentials
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

      // entra_service_principal_not_multitenant
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

  // ── Authorization Policy (tenant-wide default user permissions) ──────────

  private async checkAuthorizationPolicy(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const policy = await this.graphGet('/policies/authorizationPolicy/authorizationPolicy');
    const defaultUserRolePermissions = policy?.defaultUserRolePermissions ?? {};

    // entra_policy_default_users_cannot_create_security_groups
    if (defaultUserRolePermissions.allowedToCreateSecurityGroups !== false) {
      findings.push(this.emit(
        'entra_policy_default_users_cannot_create_security_groups',
        { allowedToCreateSecurityGroups: defaultUserRolePermissions.allowedToCreateSecurityGroups ?? true },
        { message: 'Non-privileged users are able to create security groups via the Access Panel and the Azure administration portal.' },
      ));
    }

    // entra_policy_ensure_default_user_cannot_create_apps
    if (defaultUserRolePermissions.allowedToCreateApps !== false) {
      findings.push(this.emit(
        'entra_policy_ensure_default_user_cannot_create_apps',
        { allowedToCreateApps: defaultUserRolePermissions.allowedToCreateApps ?? true },
        { message: 'App creation is not disabled for non-admin users.' },
      ));
    }

    // entra_policy_ensure_default_user_cannot_create_tenants
    if (defaultUserRolePermissions.allowedToCreateTenants !== false) {
      findings.push(this.emit(
        'entra_policy_ensure_default_user_cannot_create_tenants',
        { allowedToCreateTenants: defaultUserRolePermissions.allowedToCreateTenants ?? true },
        { message: 'Tenants creation is not disabled for non-admin users.' },
      ));
    }

    // entra_policy_guest_invite_only_for_admin_roles
    const guestInviteSettings = policy?.allowInvitesFrom ?? 'everyone';
    if (guestInviteSettings !== 'adminsAndGuestInviters' && guestInviteSettings !== 'none') {
      findings.push(this.emit(
        'entra_policy_guest_invite_only_for_admin_roles',
        { allowInvitesFrom: guestInviteSettings },
        { message: 'Guest invitations are not restricted to users with specific administrative roles only.' },
      ));
    }

    // entra_policy_guest_users_access_restrictions
    if (policy?.guestUserRoleId !== GUEST_USER_ACCESS_RESTRICTED) {
      findings.push(this.emit(
        'entra_policy_guest_users_access_restrictions',
        { guestUserRoleId: policy?.guestUserRoleId ?? null },
        { message: 'Guest user access is not restricted to properties and memberships of their own directory objects.' },
      ));
    }

    // entra_policy_restricts_user_consent_for_apps
    const grantPolicies: string[] = defaultUserRolePermissions.permissionGrantPoliciesAssigned
      ?? ['ManagePermissionGrantsForSelf.microsoft-user-default-legacy'];
    const hasSelfConsent = grantPolicies.some((p: string) => p.includes('ManagePermissionGrantsForSelf'));
    if (hasSelfConsent) {
      findings.push(this.emit(
        'entra_policy_restricts_user_consent_for_apps',
        { permissionGrantPoliciesAssigned: grantPolicies },
        { message: 'Entra allows users to consent to apps accessing company data on their behalf.' },
      ));
    }

    // entra_policy_user_consent_for_verified_apps
    const hasLegacyConsent = grantPolicies.some((p: string) =>
      p.includes('ManagePermissionGrantsForSelf.microsoft-user-default-legacy'));
    if (hasLegacyConsent) {
      findings.push(this.emit(
        'entra_policy_user_consent_for_verified_apps',
        { permissionGrantPoliciesAssigned: grantPolicies },
        { message: 'Entra allows users to consent to apps accessing company data on their behalf without restricting to verified publishers.' },
      ));
    }

    return findings;
  }

  // ── Security Defaults ──────────────────────────────────────────────────────

  private async checkSecurityDefaults(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const policy = await this.graphGet('/policies/identitySecurityDefaultsEnforcementPolicy');

    if (!policy?.isEnabled) {
      findings.push(this.emit(
        'entra_security_defaults_enabled',
        { isEnabled: policy?.isEnabled ?? false },
        { message: 'Entra security defaults is disabled.' },
      ));
    }

    return findings;
  }

  // ── Trusted Named Locations ─────────────────────────────────────────────────

  private async checkTrustedNamedLocations(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const namedLocations = await this.graphGetAll('/identity/conditionalAccess/namedLocations');

    const trustedWithRanges = namedLocations.filter((loc: any) =>
      loc.isTrusted === true && Array.isArray(loc.ipRanges) && loc.ipRanges.length > 0);

    if (trustedWithRanges.length === 0) {
      findings.push(this.emit(
        'entra_trusted_named_locations_exists',
        { namedLocationCount: namedLocations.length },
        { message: 'There is no trusted location with IP ranges defined.' },
      ));
    }

    return findings;
  }

  // ── Group Creation Settings (Group.Unified directory setting) ────────────

  private async checkGroupCreationSettings(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const data = await this.graphGet('/settings');
    const settings: any[] = data.value ?? [];
    const groupUnified = settings.find((s: any) => s.displayName === 'Group.Unified' || s.name === 'Group.Unified');

    if (!groupUnified) {
      // No directory setting override present means the tenant default (creation allowed) is in effect.
      findings.push(this.emit(
        'entra_users_cannot_create_microsoft_365_groups',
        {},
        { message: 'Users can create Microsoft 365 groups (no Group.Unified directory setting override is configured, so the tenant default applies).' },
      ));
      return findings;
    }

    const enableGroupCreation = (groupUnified.values ?? []).find((v: any) => v.name === 'EnableGroupCreation');
    if (!enableGroupCreation || enableGroupCreation.value === 'true') {
      findings.push(this.emit(
        'entra_users_cannot_create_microsoft_365_groups',
        { enableGroupCreation: enableGroupCreation?.value ?? 'true' },
        { message: 'Users can create Microsoft 365 groups.' },
      ));
    }

    return findings;
  }

  // ── App Registration Credential Hygiene ───────────────────────────────────

  private async checkAppRegistrationCredentials(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const apps = await this.graphGetAll('/applications?$select=id,displayName,appId,keyCredentials,passwordCredentials');

    const now = new Date();
    const flagged: any[] = [];

    for (const app of apps) {
      const creds = [
        ...(app.keyCredentials ?? []).map((c: any) => ({ ...c, credentialType: 'certificate' })),
        ...(app.passwordCredentials ?? []).map((c: any) => ({ ...c, credentialType: 'password' })),
      ];

      for (const cred of creds) {
        if (!cred.endDateTime) {
          flagged.push({ app: app.displayName, type: cred.credentialType, reason: 'no expiration date' });
          continue;
        }
        const end = new Date(cred.endDateTime);
        if (end <= now) {
          flagged.push({ app: app.displayName, type: cred.credentialType, reason: 'expired', expiry: cred.endDateTime });
        } else {
          const daysLeft = Math.floor((end.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));
          if (daysLeft <= APP_REGISTRATION_CRED_EXPIRY_WARNING_DAYS) {
            flagged.push({ app: app.displayName, type: cred.credentialType, reason: `expiring in ${daysLeft} days`, expiry: cred.endDateTime });
          }
        }
      }
    }

    if (flagged.length > 0) {
      findings.push(this.emit(
        'entra_app_registration_credential_not_expired',
        { count: flagged.length, credentials: flagged.slice(0, 10) },
        { message: `${flagged.length} app registration credential(s) are expired, expiring within 30 days, or have no expiration date: ${flagged.slice(0, 5).map(f => `${f.app} (${f.reason})`).join(', ')}.` },
      ));
    }

    return findings;
  }

  // ── Authentication Methods Policy ─────────────────────────────────────────

  private async checkAuthenticationMethodsPolicy(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const policy = await this.graphGet('/policies/authenticationMethodsPolicy');

    const registrationEnabled = policy?.registrationEnforcement?.authenticationMethodsRegistrationCampaign?.state === 'enabled';
    const methodConfigs: any[] = policy?.authenticationMethodConfigurations ?? [];
    const enabledStrong = methodConfigs
      .filter((c: any) => c.state === 'enabled' && STRONG_AUTH_METHODS.has(this.normalizeMethodId(c.id)))
      .map((c: any) => c.id);

    if (!registrationEnabled || enabledStrong.length === 0) {
      const issues: string[] = [];
      if (!registrationEnabled) issues.push('the MFA registration campaign is not enabled');
      if (enabledStrong.length === 0) issues.push('no strong authentication methods (Microsoft Authenticator, FIDO2, or X.509 Certificate) are enabled');

      findings.push(this.emit(
        'entra_authentication_methods_policy_strong_auth_enforced',
        { registrationEnabled, enabledStrong },
        { message: `Strong authentication is not enforced: ${issues.join('; ')}.` },
      ));
    }

    return findings;
  }

  /** Graph returns method configuration resource ids like "MicrosoftAuthenticator", "Fido2", "X509Certificate" */
  private normalizeMethodId(id: string): string {
    if (!id) return '';
    const map: Record<string, string> = {
      MicrosoftAuthenticator: 'microsoftAuthenticator',
      Fido2: 'fido2',
      X509Certificate: 'x509Certificate',
    };
    return map[id] ?? (id.charAt(0).toLowerCase() + id.slice(1));
  }

  // ── User MFA & Sign-in Hygiene ─────────────────────────────────────────────
  // Shared helper: fetch users with MFA-relevant fields once, reused by the
  // privileged/non-privileged MFA checks and recent-sign-in check.

  private async listUsersWithAuthDetails(): Promise<any[]> {
    return this.graphGetAll(
      '/users?$select=id,displayName,userPrincipalName,accountEnabled,signInActivity,createdDateTime',
    );
  }

  private async isMfaCapable(userId: string): Promise<boolean> {
    try {
      const data = await this.graphGet(`/users/${userId}/authentication/methods`);
      const methods: any[] = data.value ?? [];
      // Exclude the password method itself; MFA-capable means >=1 non-password method registered
      const nonPasswordMethods = methods.filter((m: any) =>
        m['@odata.type'] !== '#microsoft.graph.passwordAuthenticationMethod');
      return nonPasswordMethods.length >= 1;
    } catch {
      return false;
    }
  }

  private async getPrivilegedUserIds(): Promise<Set<string>> {
    const assignments = await this.graphGetAll('/roleManagement/directory/roleAssignments?$expand=principal');
    const ids = new Set<string>();
    for (const a of assignments) {
      if (PRIVILEGED_DIR_ROLES.has(a.roleDefinitionId ?? '') && a.principal?.id) {
        ids.add(a.principal.id);
      }
    }
    return ids;
  }

  /**
   * entra_privileged_user_has_mfa, entra_non_privileged_user_has_mfa,
   * entra_user_with_recent_sign_in — all three iterate the same user list,
   * so they're evaluated together to avoid re-fetching /users and re-listing
   * privileged role assignments three times.
   */
  private async checkUserMfaAndSignIn(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const [users, privilegedIds] = await Promise.all([
      this.listUsersWithAuthDetails(),
      this.getPrivilegedUserIds(),
    ]);

    const enabledUsers = users.filter((u: any) => u.accountEnabled);

    // ── entra_user_with_recent_sign_in ──
    if (enabledUsers.length > 0) {
      const allNull = enabledUsers.every((u: any) => !u.signInActivity?.lastSignInDateTime);
      if (allNull) {
        findings.push(this.emit(
          'entra_user_with_recent_sign_in',
          { enabledUserCount: enabledUsers.length },
          { message: `No sign-in activity data available for any of the ${enabledUsers.length} enabled user(s). This likely means the tenant is missing Entra ID P1/P2 licensing or the required Graph permissions to read sign-in activity.` },
        ));
      } else {
        const staleUsers = enabledUsers.filter((u: any) => {
          const last = u.signInActivity?.lastSignInDateTime;
          if (!last) return true;
          const daysSince = Math.floor((Date.now() - new Date(last).getTime()) / (24 * 60 * 60 * 1000));
          return daysSince > STALE_USER_SIGNIN_THRESHOLD_DAYS;
        });

        if (staleUsers.length > 0) {
          findings.push(this.emit(
            'entra_user_with_recent_sign_in',
            {
              count: staleUsers.length,
              users: staleUsers.slice(0, 10).map((u: any) => ({
                upn: u.userPrincipalName,
                lastSignIn: u.signInActivity?.lastSignInDateTime ?? 'never',
              })),
            },
            { message: `${staleUsers.length} enabled user(s) have not signed in for more than ${STALE_USER_SIGNIN_THRESHOLD_DAYS} days, or have never signed in.` },
          ));
        }
      }
    }

    // ── entra_privileged_user_has_mfa / entra_non_privileged_user_has_mfa ──
    // Capped: checking MFA capability requires one Graph call per user, so
    // limit to a bounded sample to avoid excessive API calls on large tenants.
    const USER_MFA_CHECK_CAP = 200;
    const usersToCheck = enabledUsers.slice(0, USER_MFA_CHECK_CAP);

    const privilegedWithoutMfa: any[] = [];
    const nonPrivilegedWithoutMfa: any[] = [];

    for (const user of usersToCheck) {
      const mfaCapable = await this.isMfaCapable(user.id);
      if (mfaCapable) continue;
      if (privilegedIds.has(user.id)) {
        privilegedWithoutMfa.push(user);
      } else {
        nonPrivilegedWithoutMfa.push(user);
      }
    }

    if (privilegedWithoutMfa.length > 0) {
      findings.push(this.emit(
        'entra_privileged_user_has_mfa',
        { count: privilegedWithoutMfa.length, users: privilegedWithoutMfa.slice(0, 10).map((u: any) => u.userPrincipalName) },
        { message: `${privilegedWithoutMfa.length} privileged user(s) do not have MFA enrolled: ${privilegedWithoutMfa.slice(0, 5).map((u: any) => u.userPrincipalName).join(', ')}.` },
      ));
    }

    if (nonPrivilegedWithoutMfa.length > 0) {
      findings.push(this.emit(
        'entra_non_privileged_user_has_mfa',
        { count: nonPrivilegedWithoutMfa.length, sample: nonPrivilegedWithoutMfa.slice(0, 10).map((u: any) => u.userPrincipalName) },
        { message: `${nonPrivilegedWithoutMfa.length} non-privileged user(s) (of ${usersToCheck.length} sampled) do not have MFA enrolled.` },
      ));
    }

    return findings;
  }

  private async checkUserVmAccessMfa(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const authClient = this.client.authorization();
      const scope = `/subscriptions/${this.client.subscriptionId}`;
      const assignments: any[] = [];
      const iter = authClient.roleAssignments.listForScope(scope, { filter: 'atScope()' });
      for await (const a of iter) assignments.push(a);

      const vmAccessPrincipalIds = new Set<string>();
      for (const a of assignments) {
        const roleId = (a.roleDefinitionId ?? '').split('/').pop() ?? '';
        if (VM_ACCESS_ROLE_IDS.has(roleId) && a.principalType === 'User' && a.principalId) {
          vmAccessPrincipalIds.add(a.principalId);
        }
      }

      if (vmAccessPrincipalIds.size === 0) return findings;

      const flagged: any[] = [];
      for (const principalId of vmAccessPrincipalIds) {
        const mfaCapable = await this.isMfaCapable(principalId);
        if (!mfaCapable) flagged.push(principalId);
      }

      if (flagged.length > 0) {
        findings.push(this.emit(
          'entra_user_with_vm_access_has_mfa',
          { count: flagged.length, userIds: flagged.slice(0, 10) },
          { message: `${flagged.length} user(s) with Azure roles granting VM sign-in or management access do not have MFA enrolled.` },
        ));
      }
    } catch {
      /* Requires ARM Authorization + Graph auth methods permissions — skip gracefully if unavailable */
    }

    return findings;
  }
}
