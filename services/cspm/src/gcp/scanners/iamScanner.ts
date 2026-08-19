import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const PRIMITIVE_ROLES   = ['roles/owner', 'roles/editor', 'roles/viewer'];
const SENSITIVE_ROLES   = ['roles/owner', 'roles/editor', 'roles/iam.securityAdmin', 'roles/resourcemanager.organizationAdmin'];
const MAX_KEY_AGE_DAYS  = 90;

export class GcpIAMScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-IAM');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      // 1. Fetch project-level IAM policy
      await this.checkProjectPolicy(project, findings);

      // 2. Enumerate service accounts and their keys
      await this.checkServiceAccounts(project, findings);

    } catch (err) {
      findings.push(this.finding(
        'GCP IAM scan error',
        `Could not complete IAM scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service account has the roles/iam.securityReviewer permission.',
      ));
    }

    return findings;
  }

  private async checkProjectPolicy(project: string, findings: ScanningResult[]): Promise<void> {
    try {
      const crm = this.client.cloudresourcemanagerV1();
      const res  = await crm.projects.getIamPolicy({ resource: project, requestBody: {} });
      const policy = res.data;
      const bindings = policy.bindings ?? [];

      // 1a. Primitive roles (Owner/Editor) at project level
      const primitiveBindings = bindings.filter(b => PRIMITIVE_ROLES.includes(b.role ?? ''));
      for (const b of primitiveBindings) {
        const members = b.members ?? [];
        if (members.length > 0) {
          findings.push(this.emit(
            'iam_no_primitive_roles_at_project_level',
            { project, role: b.role, members: members.slice(0, 10), memberCount: members.length },
            {
              message: `The project "${project}" has ${members.length} member(s) bound to the primitive role "${b.role}". Primitive roles (Owner, Editor, Viewer) grant overly broad permissions across all GCP services.`,
              remediation: `Replace primitive roles with predefined or custom roles that follow least privilege. For "${b.role}", identify the specific GCP services needed and grant those service-specific roles instead.`,
              severity: b.role === 'roles/owner' ? 'CRITICAL' : 'HIGH',
            },
          ));
        }
      }

      // 1b. allUsers / allAuthenticatedUsers in any binding
      for (const b of bindings) {
        const members   = b.members ?? [];
        const isPublic  = members.includes('allUsers');
        const isAuthAll = members.includes('allAuthenticatedUsers');
        if (isPublic || isAuthAll) {
          findings.push(this.emit(
            'iam_no_public_access_bindings',
            { project, role: b.role, publicMembers: members.filter(m => m === 'allUsers' || m === 'allAuthenticatedUsers') },
            {
              message: `The project "${project}" IAM policy for role "${b.role}" includes "${isPublic ? 'allUsers' : 'allAuthenticatedUsers'}". This makes the associated resources accessible to the general public.`,
            },
          ));
        }
      }

      // 1c. Count unique Owner members
      const ownerBinding = bindings.find(b => b.role === 'roles/owner');
      const owners       = ownerBinding?.members ?? [];
      if (owners.length > 3) {
        findings.push(this.emit(
          'iam_owner_role_assignments_limited',
          { project, ownerCount: owners.length, owners: owners.slice(0, 10) },
          {
            message: `The project "${project}" has ${owners.length} members with the Owner role. A compromised owner account has unrestricted access to all GCP resources, data, and billing.`,
          },
        ));
      }

      // 1d. External users (non-@project.iam.gserviceaccount.com, non-group) in sensitive roles
      for (const b of bindings) {
        if (!SENSITIVE_ROLES.includes(b.role ?? '')) continue;
        const extUsers = (b.members ?? []).filter(m =>
          m.startsWith('user:') && !m.includes('.gserviceaccount.com'),
        );
        if (extUsers.length > 0) {
          findings.push(this.emit(
            'iam_sensitive_roles_not_granted_to_individual_users',
            { project, role: b.role, users: extUsers.slice(0, 10) },
            {
              message: `The project "${project}" has ${extUsers.length} individual user(s) with "${b.role}": ${extUsers.slice(0, 5).join(', ')}. Individual user accounts are harder to manage than groups and bypass group-based access controls.`,
            },
          ));
        }
      }
    } catch { /* optional */ }
  }

  private async checkServiceAccounts(project: string, findings: ScanningResult[]): Promise<void> {
    try {
      const iam = this.client.iam();
      const res  = await iam.projects.serviceAccounts.list({ name: `projects/${project}` });
      const accounts = res.data.accounts ?? [];

      if (accounts.length > 0) {
        // Check: too many service accounts
        if (accounts.length > 50) {
          findings.push(this.emit(
            'iam_service_account_count_reasonable',
            { project, serviceAccountCount: accounts.length },
            {
              message: `The project "${project}" has ${accounts.length} service accounts. A large number of service accounts increases the attack surface and makes access auditing difficult.`,
            },
          ));
        }
      }

      // Check each service account's keys
      for (const sa of accounts) {
        if (!sa.name) continue;
        try {
          const keysRes = await iam.projects.serviceAccounts.keys.list({
            name: sa.name,
            keyTypes: ['USER_MANAGED'],
          });
          const keys = (keysRes.data.keys ?? []).filter(k => k.keyType === 'USER_MANAGED');

          if (keys.length > 0) {
            findings.push(this.emit(
              'iam_sa_no_user_managed_keys',
              { project, serviceAccount: sa.email, keyCount: keys.length },
              { message: `Service account "${sa.email}" in project "${project}" has ${keys.length} user-managed key(s). User-managed keys are long-lived credentials that can be extracted from code repositories or misconfigured storage, leading to account compromise.` },
            ));
          }

          // Check for old keys
          for (const key of keys) {
            const created = key.validAfterTime ? new Date(key.validAfterTime) : null;
            if (created) {
              const ageDays = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24);
              if (ageDays > MAX_KEY_AGE_DAYS) {
                findings.push(this.emit(
                  'iam_sa_key_rotation_90_days',
                  { project, serviceAccount: sa.email, keyId: key.name?.split('/').pop(), ageDays: Math.round(ageDays) },
                  {
                    message: `Service account "${sa.email}" has key "${key.name?.split('/').pop()}" that was created ${Math.round(ageDays)} days ago. Stale keys represent credentials that may have been exfiltrated and are still valid.`,
                  },
                ));
              }
            }
          }
        } catch { /* key check optional per SA */ }
      }

      // Check for default service account with editor role
      const defaultSA = accounts.find(a =>
        a.email?.startsWith('compute@developer.gserviceaccount.com') ||
        a.email?.includes('-compute@developer.gserviceaccount.com'),
      );
      if (defaultSA) {
        findings.push(this.emit(
          'iam_default_compute_sa_no_editor_role',
          { project, defaultServiceAccount: defaultSA.email },
          {
            message: `The project "${project}" has a default Compute Engine service account "${defaultSA.email}". By default, this account is granted the Editor role, giving all VM instances broad write access to GCP APIs.`,
          },
        ));
      }

    } catch { /* optional */ }
  }
}
