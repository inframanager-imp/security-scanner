import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

/** Privileged built-in role IDs (last segment of the full definition ID) */
const PRIVILEGED_ROLE_IDS = new Set([
  '8e3af657-a8ff-443c-a75c-2fe8c4bcb635', // Owner
  'b24988ac-6180-42a0-ab88-20f7382dd24c', // Contributor
  '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9', // User Access Administrator
  '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', // Application Administrator
  '62e90394-69f5-4237-9190-012177145e10', // Global Administrator (AAD — informational)
]);

export class AzureIAMScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-IAM');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const authClient = this.client.authorization();

    try {
      const scope = `/subscriptions/${this.client.subscriptionId}`;
      const assignments: any[] = [];
      const iter = authClient.roleAssignments.listForScope(scope, { filter: 'atScope()' });
      for await (const a of iter) assignments.push(a);

      // ── 1. Excessive subscription-level Owner/Contributor ─────────────────
      const subscriptionOwners = assignments.filter(a => {
        const roleId = (a.roleDefinitionId ?? '').split('/').pop() ?? '';
        return (
          roleId === '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' || // Owner
          roleId === 'b24988ac-6180-42a0-ab88-20f7382dd24c'    // Contributor
        ) && a.scope === scope;
      });

      if (subscriptionOwners.length > 3) {
        findings.push(this.finding(
          'Excessive subscription-level Owner/Contributor assignments',
          `${subscriptionOwners.length} principals have Owner or Contributor role directly at subscription scope. This grants unrestricted control over all resources.`,
          'HIGH',
          { count: subscriptionOwners.length, principals: subscriptionOwners.slice(0, 10).map(a => a.principalId) },
          'Apply the principle of least privilege. Use resource-group-scoped roles instead of subscription-level Owner/Contributor. Review and remove unnecessary assignments.',
          ['iam', 'rbac'],
        ));
      }

      // ── 2. Service principals with subscription-level Owner ───────────────
      const spOwners = assignments.filter(a => {
        const roleId = (a.roleDefinitionId ?? '').split('/').pop() ?? '';
        return roleId === '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' &&
          a.principalType === 'ServicePrincipal' &&
          a.scope === scope;
      });

      if (spOwners.length > 0) {
        findings.push(this.finding(
          'Service principals with subscription Owner role',
          `${spOwners.length} service principal(s) have the Owner role at subscription scope: ${spOwners.map(a => a.principalId).join(', ')}. Compromised service principal credentials with Owner access can lead to full subscription takeover.`,
          'CRITICAL',
          { count: spOwners.length, principalIds: spOwners.map(a => a.principalId) },
          'Remove subscription Owner from all service principals. Replace with least-privilege roles scoped to specific resource groups. Use managed identities where possible to eliminate credentials entirely.',
          ['iam', 'service-principal', 'rbac'],
        ));
      }

      // ── 3. Orphaned role assignments (principal no longer exists) ─────────
      const orphaned = assignments.filter(a =>
        !a.principalId ||
        a.condition?.includes('$deleted') ||
        // ARM returns these as "DeletedPrincipal" or empty display
        (a.principalType === 'Unknown'),
      );

      if (orphaned.length > 0) {
        findings.push(this.finding(
          'Orphaned role assignments — principal no longer exists',
          `${orphaned.length} role assignment(s) reference principals that no longer exist in Azure AD (deleted users, groups, or service principals). Orphaned assignments waste permissions headroom and create confusion during access reviews.`,
          'LOW',
          { count: orphaned.length, assignmentIds: orphaned.slice(0, 10).map(a => a.id) },
          'Remove orphaned role assignments. Use "az role assignment list --include-inherited" to identify all assignments, then delete those with non-existent principals.',
          ['iam', 'rbac', 'orphaned'],
        ));
      }

      // ── 4. High number of total privileged assignments ────────────────────
      const privilegedAssignments = assignments.filter(a => {
        const roleId = (a.roleDefinitionId ?? '').split('/').pop() ?? '';
        return PRIVILEGED_ROLE_IDS.has(roleId);
      });

      if (privilegedAssignments.length > 5) {
        findings.push(this.finding(
          'High number of privileged role assignments',
          `${privilegedAssignments.length} privileged role assignments detected across the subscription. Excessive privileged access increases the blast radius of a compromise.`,
          'MEDIUM',
          { count: privilegedAssignments.length },
          'Regularly audit privileged role assignments using Azure AD Access Reviews. Remove stale or unnecessary assignments. Use PIM for just-in-time access.',
          ['iam', 'rbac'],
        ));
      }

      // ── 5. Classic co-administrators (legacy) ─────────────────────────────
      try {
        const classicAdmins: any[] = [];
        for await (const ca of authClient.classicAdministrators.list()) classicAdmins.push(ca);
        if (classicAdmins.length > 0) {
          findings.push(this.finding(
            'Classic co-administrator accounts detected',
            `${classicAdmins.length} classic co-administrator account(s) found. Classic roles predate Azure RBAC and grant broad management access without RBAC audit trails.`,
            'HIGH',
            { accounts: classicAdmins.map(a => a.emailAddress) },
            'Migrate all classic co-administrators to equivalent Azure RBAC roles and remove the legacy assignments.',
            ['iam', 'legacy'],
          ));
        }
      } catch { /* API may not be available */ }

      // ── 6. Guest users in privileged roles ────────────────────────────────
      const guestPrivileged = assignments.filter(a => {
        const roleId = (a.roleDefinitionId ?? '').split('/').pop() ?? '';
        return PRIVILEGED_ROLE_IDS.has(roleId) &&
          (a.principalType === 'ForeignGroup' || a.principalType === 'Guest');
      });
      if (guestPrivileged.length > 0) {
        findings.push(this.finding(
          'Guest users assigned privileged Azure roles',
          `${guestPrivileged.length} guest/external user(s) have privileged Azure RBAC roles on this subscription.`,
          'HIGH',
          { count: guestPrivileged.length },
          'Review all guest user role assignments. Remove or downgrade permissions for external users where not operationally required.',
          ['iam', 'guest'],
        ));
      }

      // ── 7. Custom roles with wildcard (*) actions ─────────────────────────
      try {
        const roleDefs: any[] = [];
        for await (const rd of authClient.roleDefinitions.list(scope)) roleDefs.push(rd);

        const customRoles = roleDefs.filter(rd => rd.roleType === 'CustomRole');
        const wildcardRoles = customRoles.filter(rd => {
          const perms = rd.permissions ?? [];
          return perms.some((p: any) =>
            (p.actions ?? []).some((a: string) => a === '*') ||
            (p.dataActions ?? []).some((a: string) => a === '*'),
          );
        });

        if (wildcardRoles.length > 0) {
          findings.push(this.finding(
            'Custom role definitions with wildcard (*) permissions',
            `${wildcardRoles.length} custom RBAC role(s) grant wildcard (*) permissions: ${wildcardRoles.map(r => r.roleName).join(', ')}. Wildcard actions grant all current and future permissions in a provider namespace.`,
            'HIGH',
            {
              count: wildcardRoles.length,
              roles: wildcardRoles.map(r => ({ name: r.roleName, id: r.name })),
            },
            'Replace wildcard actions with specific permission lists. Use the principle of least privilege — enumerate only the exact actions the role needs.',
            ['iam', 'custom-role', 'rbac'],
          ));
        }

        // Unused custom roles (no assignments)
        const assignedRoleDefIds = new Set(assignments.map(a => (a.roleDefinitionId ?? '').split('/').pop()));
        const unusedCustomRoles = customRoles.filter(rd => !assignedRoleDefIds.has(rd.name));
        if (unusedCustomRoles.length > 0) {
          findings.push(this.finding(
            'Unused custom role definitions detected',
            `${unusedCustomRoles.length} custom role definition(s) have no current assignments: ${unusedCustomRoles.slice(0, 5).map(r => r.roleName).join(', ')}. Unused roles accumulate technical debt and may contain overly broad permissions.`,
            'LOW',
            { count: unusedCustomRoles.length, roles: unusedCustomRoles.map(r => r.roleName) },
            'Review and delete unused custom role definitions. Keep only roles with active assignments.',
            ['iam', 'custom-role', 'hygiene'],
          ));
        }
      } catch { /* role definition listing optional */ }

      // ── 8. Managed identity risk analysis ────────────────────────────────
      await this.checkManagedIdentities(findings, authClient, scope);

    } catch (err) {
      findings.push(this.finding(
        'Azure IAM scan error',
        `Could not complete IAM scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader and User Access Administrator read permissions.',
      ));
    }

    return findings;
  }

  private async checkManagedIdentities(
    findings: ScanningResult[],
    authClient: ReturnType<import('../client').AzureClient['authorization']>,
    scope: string,
  ): Promise<void> {
    try {
      // Get all user-assigned managed identities
      const uamiClient = this.client.managedIdentity();
      const uamis: any[] = [];
      for await (const mi of uamiClient.userAssignedIdentities.listBySubscription()) uamis.push(mi);

      if (uamis.length === 0) return;

      // Get all role assignments for managed identities
      const miAssignments: any[] = [];
      for await (const a of authClient.roleAssignments.listForScope(scope)) {
        if (a.principalType === 'ServicePrincipal') miAssignments.push(a);
      }

      const miPrincipalIds = new Set(uamis.map(mi => mi.principalId).filter(Boolean));

      // Identify MIs with no role assignments (assigned to resources but no permissions)
      const unusedMIs = uamis.filter(mi => {
        const hasAssignment = miAssignments.some(a => a.principalId === mi.principalId);
        return !hasAssignment;
      });

      if (unusedMIs.length > 0) {
        findings.push(this.finding(
          'User-assigned managed identities with no role assignments',
          `${unusedMIs.length} user-assigned managed identity/identities have no Azure RBAC role assignments: ${unusedMIs.slice(0, 5).map(mi => mi.name).join(', ')}. Identities without permissions may be orphaned or misconfigured.`,
          'LOW',
          {
            count: unusedMIs.length,
            identities: unusedMIs.slice(0, 10).map(mi => ({ name: mi.name, rg: mi.id?.split('/')[4] })),
          },
          'Review unused managed identities. Delete identities not attached to any resource. Ensure assigned identities have the minimum required role assignments.',
          ['iam', 'managed-identity', 'orphaned'],
        ));
      }

      // Identify MIs with subscription-level Owner or Contributor
      const overprivilegedMIs = miAssignments.filter(a => {
        const roleId = (a.roleDefinitionId ?? '').split('/').pop() ?? '';
        return miPrincipalIds.has(a.principalId ?? '') &&
          (roleId === '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' || // Owner
           roleId === 'b24988ac-6180-42a0-ab88-20f7382dd24c')   // Contributor
          && a.scope === scope;
      });

      if (overprivilegedMIs.length > 0) {
        findings.push(this.finding(
          'Managed identities with subscription-level Owner or Contributor',
          `${overprivilegedMIs.length} managed identity/identities have Owner or Contributor at subscription scope. If the resource hosting the identity is compromised, the attacker gains full subscription control.`,
          'CRITICAL',
          {
            count: overprivilegedMIs.length,
            principalIds: overprivilegedMIs.map(a => a.principalId),
          },
          'Reduce managed identity permissions to the minimum required scope (resource group or specific resource). Replace subscription-level Owner/Contributor with narrowly scoped roles.',
          ['iam', 'managed-identity', 'over-privileged'],
        ));
      }

    } catch { /* managed identity checks optional */ }
  }
}
