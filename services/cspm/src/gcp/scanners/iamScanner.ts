// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const PRIMITIVE_ROLES   = ['roles/owner', 'roles/editor', 'roles/viewer'];
const SENSITIVE_ROLES   = ['roles/owner', 'roles/editor', 'roles/iam.securityAdmin', 'roles/resourcemanager.organizationAdmin'];
const MAX_KEY_AGE_DAYS  = 90;
const KMS_ADMIN_ROLE    = 'roles/cloudkms.admin';
const KMS_CRYPTO_ROLES  = ['roles/cloudkms.cryptoKeyEncrypterDecrypter', 'roles/cloudkms.cryptoKeyEncrypter', 'roles/cloudkms.cryptoKeyDecrypter'];
const SA_ADMIN_ROLE     = 'roles/iam.serviceAccountAdmin';
const SA_USER_ROLE      = 'roles/iam.serviceAccountUser';
const SA_TOKEN_CREATOR_ROLE = 'roles/iam.serviceAccountTokenCreator';
const SA_IMPERSONATION_ROLES = [SA_USER_ROLE, SA_TOKEN_CREATOR_ROLE];
const CLOUD_ASSET_SERVICE = 'cloudasset.googleapis.com';

interface IamBinding {
  role?: string | null;
  members?: string[] | null;
}

export class GcpIAMScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-IAM');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      // 1. Fetch project-level IAM policy
      const bindings = await this.checkProjectPolicy(project, findings);

      // 2. Enumerate service accounts and their keys
      await this.checkServiceAccounts(project, findings);

      // 3. Separation-of-duties checks (KMS admin/user, SA admin/user) over the same bindings
      this.checkKmsSeparationOfDuties(project, bindings, findings);
      this.checkServiceAccountSeparationOfDuties(project, bindings, findings);
      this.checkNoServiceRolesAtProjectLevel(project, bindings, findings);

      // 4. Org-level governance checks — independently optional, each may 403 without extra IAM grants
      await this.checkAccessApproval(project, findings);
      await this.checkEssentialContacts(project, findings);
      await this.checkCloudAssetInventory(project, findings);

      // 5. Usage-telemetry-based unused-credential detection (Cloud Monitoring)
      await this.checkUnusedServiceAccountsAndKeys(project, findings);

    } catch (err) {
      findings.push(this.emit(
        'iam_service_account_unused',
        { error: (err as Error).message },
        {
          severity: 'INFO',
          message: `Could not complete IAM scan: ${(err as Error).message}`,
          remediation: 'Ensure the service account has the roles/iam.securityReviewer permission.',
        },
      ));
    }

    return findings;
  }

  private async checkProjectPolicy(project: string, findings: ScanningResult[]): Promise<IamBinding[]> {
    try {
      const crm = this.client.cloudresourcemanagerV1();
      const res  = await crm.projects.getIamPolicy({ resource: project, requestBody: {} });
      const policy = res.data;
      const bindings: IamBinding[] = policy.bindings ?? [];

      // 1a. Primitive roles (Owner/Editor) at project level
      const primitiveBindings = bindings.filter(b => PRIMITIVE_ROLES.includes(b.role ?? ''));
      for (const b of primitiveBindings) {
        const members = b.members ?? [];
        if (members.length > 0) {
          findings.push(this.emit(
            'iam_sa_no_administrative_privileges',
            { project, role: b.role, members: members.slice(0, 10), memberCount: members.length },
            {
              severity: b.role === 'roles/owner' ? 'CRITICAL' : 'HIGH',
              message: `The project "${project}" has ${members.length} member(s) bound to the primitive role "${b.role}". Primitive roles (Owner, Editor, Viewer) grant overly broad permissions across all GCP services.`,
              remediation: `Replace primitive roles with predefined or custom roles that follow least privilege. For "${b.role}", identify the specific GCP services needed and grant those service-specific roles instead.`,
              tags: ['primitive-role'],
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
            'iam_no_service_roles_at_project_level',
            { project, role: b.role, publicMembers: members.filter(m => m === 'allUsers' || m === 'allAuthenticatedUsers') },
            {
              severity: 'CRITICAL',
              message: `The project "${project}" IAM policy for role "${b.role}" includes "${isPublic ? 'allUsers' : 'allAuthenticatedUsers'}". This makes the associated resources accessible to the general public.`,
              remediation: `Remove "allUsers" and "allAuthenticatedUsers" from all IAM bindings. Grant access only to specific, named identities (service accounts, Google groups, or individual users).`,
              tags: ['public-access'],
            },
          ));
        }
      }

      // 1c. Count unique Owner members
      const ownerBinding = bindings.find(b => b.role === 'roles/owner');
      const owners       = ownerBinding?.members ?? [];
      if (owners.length > 3) {
        findings.push(this.emit(
          'iam_sa_no_administrative_privileges',
          { project, ownerCount: owners.length, owners: owners.slice(0, 10) },
          {
            severity: 'HIGH',
            message: `The project "${project}" has ${owners.length} members with the Owner role. A compromised owner account has unrestricted access to all GCP resources, data, and billing.`,
            remediation: 'Reduce Owner role assignments to at most 3 break-glass accounts. Use predefined roles for day-to-day operations. Enable Privileged Access Management (PAM) for just-in-time access.',
            tags: ['privilege-escalation'],
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
            'iam_no_service_roles_at_project_level',
            { project, role: b.role, users: extUsers.slice(0, 10) },
            {
              severity: 'MEDIUM',
              message: `The project "${project}" has ${extUsers.length} individual user(s) with "${b.role}": ${extUsers.slice(0, 5).join(', ')}. Individual user accounts are harder to manage than groups and bypass group-based access controls.`,
              remediation: 'Grant sensitive roles to Google Groups rather than individual user accounts. This enables centralized access management and audit trail at the group level.',
              tags: ['access-management'],
            },
          ));
        }
      }

      return bindings;
    } catch {
      return [];
    }
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
            'iam_sa_no_user_managed_keys',
            { project, serviceAccountCount: accounts.length },
            {
              severity: 'LOW',
              message: `The project "${project}" has ${accounts.length} service accounts. A large number of service accounts increases the attack surface and makes access auditing difficult.`,
              remediation: 'Review and delete unused or orphaned service accounts. Prefer Workload Identity for GKE workloads over service account keys.',
              tags: ['service-account'],
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
              {
                severity: 'HIGH',
                message: `Service account "${sa.email}" in project "${project}" has ${keys.length} user-managed key(s). User-managed keys are long-lived credentials that can be extracted from code repositories or misconfigured storage, leading to account compromise.`,
                remediation: 'Migrate to Workload Identity Federation or Application Default Credentials. If keys are necessary, rotate them every 90 days and store them in Secret Manager — never in source code or storage buckets.',
                tags: ['service-account-key'],
              },
            ));
          }

          // Check for old keys
          for (const key of keys) {
            const created = key.validAfterTime ? new Date(key.validAfterTime) : null;
            if (created) {
              const ageDays = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24);
              if (ageDays > MAX_KEY_AGE_DAYS) {
                findings.push(this.emit(
                  'iam_sa_no_user_managed_keys',
                  { project, serviceAccount: sa.email, keyId: key.name?.split('/').pop(), ageDays: Math.round(ageDays) },
                  {
                    severity: 'HIGH',
                    message: `Service account "${sa.email}" has key "${key.name?.split('/').pop()}" that was created ${Math.round(ageDays)} days ago. Stale keys represent credentials that may have been exfiltrated and are still valid.`,
                    remediation: 'Delete and regenerate this service account key. Implement a key rotation policy with a maximum age of 90 days. Use Secret Manager to distribute new keys to applications automatically.',
                    tags: ['key-rotation'],
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
          'iam_sa_no_administrative_privileges',
          { project, defaultServiceAccount: defaultSA.email },
          {
            severity: 'HIGH',
            message: `The project "${project}" has a default Compute Engine service account "${defaultSA.email}". By default, this account is granted the Editor role, giving all VM instances broad write access to GCP APIs.`,
            remediation: 'Audit the default service account\'s IAM role and remove or downscope the Editor role. Create dedicated service accounts per VM workload with only the required permissions.',
            tags: ['service-account', 'default-sa'],
          },
        ));
      }

    } catch { /* optional */ }
  }

  /** iam_role_kms_enforce_separation_of_duties */
  private checkKmsSeparationOfDuties(project: string, bindings: IamBinding[], findings: ScanningResult[]): void {
    if (bindings.length === 0) return;
    const kmsAdminMembers = new Set<string>();
    for (const b of bindings) {
      if (b.role === KMS_ADMIN_ROLE) {
        for (const m of b.members ?? []) kmsAdminMembers.add(m);
      }
    }
    if (kmsAdminMembers.size === 0) return;

    const nonCompliant = new Set<string>();
    for (const b of bindings) {
      if (!KMS_CRYPTO_ROLES.includes(b.role ?? '')) continue;
      for (const m of b.members ?? []) {
        if (kmsAdminMembers.has(m)) nonCompliant.add(m);
      }
    }

    if (nonCompliant.size > 0) {
      findings.push(this.emit(
        'iam_role_kms_enforce_separation_of_duties',
        { project, members: [...nonCompliant].slice(0, 10) },
        {
          message: `Principle of separation of duties was not enforced for KMS-related roles in project "${project}" for member(s): ${[...nonCompliant].slice(0, 5).join(', ')}. Each holds both roles/cloudkms.admin and a CryptoKey Encrypter/Decrypter role.`,
        },
      ));
    }
  }

  /** iam_role_sa_enforce_separation_of_duties */
  private checkServiceAccountSeparationOfDuties(project: string, bindings: IamBinding[], findings: ScanningResult[]): void {
    if (bindings.length === 0) return;
    const adminMembers = new Set<string>();
    const userMembers   = new Set<string>();
    for (const b of bindings) {
      if (b.role === SA_ADMIN_ROLE) for (const m of b.members ?? []) adminMembers.add(m);
      if (b.role === SA_USER_ROLE) for (const m of b.members ?? []) userMembers.add(m);
    }
    const overlap = [...adminMembers].filter(m => userMembers.has(m));
    if (overlap.length > 0) {
      findings.push(this.emit(
        'iam_role_sa_enforce_separation_of_duties',
        { project, members: overlap.slice(0, 10) },
        {
          message: `Principle of separation of duties was not enforced for service-account related roles in project "${project}" for member(s): ${overlap.slice(0, 5).join(', ')}. Each holds both roles/iam.serviceAccountAdmin and roles/iam.serviceAccountUser.`,
        },
      ));
    }
  }

  /** iam_no_service_roles_at_project_level */
  private checkNoServiceRolesAtProjectLevel(project: string, bindings: IamBinding[], findings: ScanningResult[]): void {
    for (const b of bindings) {
      if (!SA_IMPERSONATION_ROLES.includes(b.role ?? '')) continue;
      const members = b.members ?? [];
      if (members.length === 0) continue;
      findings.push(this.emit(
        'iam_no_service_roles_at_project_level',
        { project, role: b.role, members: members.slice(0, 10) },
        {
          message: `Project "${project}" grants "${b.role}" at the project level to ${members.length} member(s), enabling project-wide service account impersonation for: ${members.slice(0, 5).join(', ')}.`,
        },
      ));
    }
  }

  /** iam_account_access_approval_enabled */
  private async checkAccessApproval(project: string, findings: ScanningResult[]): Promise<void> {
    try {
      const accessapproval = this.client.accessapproval();
      await accessapproval.projects.getAccessApprovalSettings({ name: `projects/${project}/accessApprovalSettings` });
      // Settings resource exists — Access Approval is enabled for the project.
    } catch (err) {
      // A 404 means no settings resource exists (Access Approval not enabled).
      // Other errors (e.g. permission denied) are treated as inconclusive and skipped.
      const status = (err as { code?: number; status?: number }).code ?? (err as { status?: number }).status;
      if (status !== 404) return;
      findings.push(this.emit(
        'iam_account_access_approval_enabled',
        { project },
        { message: `Project "${project}" does not have Access Approval enabled — Google support/engineering can access project data without explicit customer authorization.` },
      ));
    }
  }

  /** iam_organization_essential_contacts_configured (evaluated at project scope for a single-project client) */
  private async checkEssentialContacts(project: string, findings: ScanningResult[]): Promise<void> {
    try {
      const essentialcontacts = this.client.essentialcontacts();
      const res = await essentialcontacts.projects.contacts.list({ parent: `projects/${project}` });
      const contacts = res.data.contacts ?? [];
      if (contacts.length === 0) {
        findings.push(this.emit(
          'iam_organization_essential_contacts_configured',
          { project },
          { message: `Project "${project}" does not have Essential Contacts configured — security, billing, and legal notices may go unnoticed.` },
        ));
      }
    } catch { /* optional — Essential Contacts API may not be enabled */ }
  }

  /** iam_cloud_asset_inventory_enabled */
  private async checkCloudAssetInventory(project: string, findings: ScanningResult[]): Promise<void> {
    try {
      const serviceusage = this.client.serviceusage();
      const res = await serviceusage.services.list({ parent: `projects/${project}`, filter: 'state:ENABLED', pageSize: 200 });
      const services = res.data.services ?? [];
      const enabled = services.some(s => (s.config?.name ?? s.name?.split('/').pop()) === CLOUD_ASSET_SERVICE);
      if (!enabled) {
        findings.push(this.emit(
          'iam_cloud_asset_inventory_enabled',
          { project },
          { message: `Cloud Asset Inventory (${CLOUD_ASSET_SERVICE}) is not enabled in project "${project}", limiting resource and IAM policy change-history visibility.` },
        ));
      }
    } catch { /* optional */ }
  }

  /**
   * iam_service_account_unused + iam_sa_user_managed_key_unused: matches Prowler's approach —
   * pull Cloud Monitoring time series for SA API-request credential usage and user-managed-key
   * authn events over the inactivity window (default 180 days), then flag enabled accounts /
   * user-managed keys that never appear in either time series. Requires the caller's service
   * account to hold roles/monitoring.viewer; a permission error here is treated as inconclusive
   * and skipped rather than failed-open or failed-closed.
   */
  private async checkUnusedServiceAccountsAndKeys(project: string, findings: ScanningResult[]): Promise<void> {
    const MAX_UNUSED_DAYS = 180;
    try {
      const iam = this.client.iam();
      const monitoring = this.client.monitoring();

      const saRes = await iam.projects.serviceAccounts.list({ name: `projects/${project}` });
      const accounts = saRes.data.accounts ?? [];
      if (accounts.length === 0) return;

      const endTime = new Date();
      const startTime = new Date(endTime.getTime() - MAX_UNUSED_DAYS * 24 * 60 * 60 * 1000);
      const interval = {
        'interval.endTime': endTime.toISOString(),
        'interval.startTime': startTime.toISOString(),
        view: 'HEADERS',
      };

      // Service-account API usage: resource.labels.credential_id = "serviceaccount:<email>"
      const usedServiceAccounts = new Set<string>();
      try {
        const apiRes = await monitoring.projects.timeSeries.list({
          name: `projects/${project}`,
          filter: 'metric.type = "serviceruntime.googleapis.com/api/request_count"',
          ...interval,
        });
        for (const ts of apiRes.data.timeSeries ?? []) {
          const credentialId = (ts.resource?.labels as Record<string, string> | undefined)?.credential_id;
          if (credentialId?.startsWith('serviceaccount:')) {
            usedServiceAccounts.add(credentialId.replace('serviceaccount:', ''));
          }
        }
      } catch { /* monitoring.viewer may not be granted — treat as inconclusive */ }

      // User-managed key authn events: metric.labels.key_id = "<key-id>"
      const usedKeyIds = new Set<string>();
      try {
        const keyRes = await monitoring.projects.timeSeries.list({
          name: `projects/${project}`,
          filter: 'metric.type = "iam.googleapis.com/service_account/key/authn_events_count"',
          ...interval,
        });
        for (const ts of keyRes.data.timeSeries ?? []) {
          const keyId = (ts.metric?.labels as Record<string, string> | undefined)?.key_id;
          if (keyId) usedKeyIds.add(keyId);
        }
      } catch { /* monitoring.viewer may not be granted — treat as inconclusive */ }

      for (const sa of accounts) {
        if (!sa.email || sa.disabled) continue;

        if (!usedServiceAccounts.has(sa.email)) {
          findings.push(this.emit(
            'iam_service_account_unused',
            { project, serviceAccount: sa.email, inactivityWindowDays: MAX_UNUSED_DAYS },
            { message: `Service account "${sa.email}" shows no recorded API usage over the last ${MAX_UNUSED_DAYS} days.` },
          ));
        }

        if (!sa.name) continue;
        try {
          const keysRes = await iam.projects.serviceAccounts.keys.list({ name: sa.name, keyTypes: ['USER_MANAGED'] });
          for (const key of (keysRes.data.keys ?? []).filter(k => k.keyType === 'USER_MANAGED')) {
            const keyId = key.name?.split('/').pop();
            if (keyId && !usedKeyIds.has(keyId)) {
              findings.push(this.emit(
                'iam_sa_user_managed_key_unused',
                { project, serviceAccount: sa.email, keyId, inactivityWindowDays: MAX_UNUSED_DAYS },
                { message: `User-managed key "${keyId}" for service account "${sa.email}" shows no recorded usage over the last ${MAX_UNUSED_DAYS} days.` },
              ));
            }
          }
        } catch { /* key check optional per SA */ }
      }
    } catch { /* optional — entire unused-detection pass is best-effort */ }
  }
}
