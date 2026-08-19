import {
  ListUsersCommand,
  ListAccessKeysCommand,
  GetLoginProfileCommand,
  ListAttachedUserPoliciesCommand,
  GetAccessKeyLastUsedCommand,
  GenerateCredentialReportCommand,
  GetCredentialReportCommand,
  GetAccountPasswordPolicyCommand,
  ListMFADevicesCommand,
  ListVirtualMFADevicesCommand,
  ListRolePoliciesCommand,
  ListAttachedRolePoliciesCommand,
  ListRolesCommand,
  GetAccountAuthorizationDetailsCommand,
} from '@aws-sdk/client-iam';
import { AccessAnalyzerClient, ListAnalyzersCommand } from '@aws-sdk/client-accessanalyzer';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry, mapWithConcurrency } from '../utils/helpers';

export class IAMScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'IAM');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting IAM security scan...');

      // List all users
      const users = await this.listAllUsers();

      // Was a sequential for-loop — 5 checks per user, one user at a time.
      // On an account with hundreds of users that's hundreds of real network
      // round-trips end to end with zero progress logged in between, which
      // is what made large-account scans look hung rather than just slow.
      const perUserFindings = await mapWithConcurrency(users, 8, async user => {
        const username = user.UserName || 'Unknown';
        logger.debug(`Scanning user: ${username}`);

        const [mfaFindings, accessKeyFindings, consoleFindings, inactiveFindings, permissionFindings] =
          await Promise.all([
            this.checkMFA(user),
            this.checkAccessKeys(username),
            this.checkConsoleAccess(username),
            this.checkInactiveUsers(user),
            this.checkPermissions(username),
          ]);

        return [...mfaFindings, ...accessKeyFindings, ...consoleFindings, ...inactiveFindings, ...permissionFindings];
      });
      findings.push(...perUserFindings.flat());

      // Check root account via credential report
      const rootFindings = await this.checkRootAccountViaReport();
      findings.push(...rootFindings);

      // Check real password policy
      const passwordFindings = await this.checkPasswordPolicyDetails();
      findings.push(...passwordFindings);

      // Check IAM Access Analyzer
      const analyzerFindings = await this.checkAccessAnalyzer();
      findings.push(...analyzerFindings);

      // Check support role
      const supportFindings = await this.checkSupportRole();
      findings.push(...supportFindings);

      // Check orphaned virtual MFA devices
      const virtualMfaFindings = await this.checkUnassignedVirtualMFADevices();
      findings.push(...virtualMfaFindings);

      // Check inline policies on roles
      const roleInlineFindings = await this.checkRoleInlinePolicies();
      findings.push(...roleInlineFindings);

      // Check for wildcard (*:*) policies across the account
      const wildcardFindings = await this.checkWildcardPolicies();
      findings.push(...wildcardFindings);

      logger.info(`IAM scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('IAM scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listAllUsers(): Promise<any[]> {
    return retry(async () => {
      logger.debug('Fetching all IAM users...');
      const users: any[] = [];
      let marker: string | undefined;

      do {
        const result = await this.client.iam.send(new ListUsersCommand({ Marker: marker }));
        users.push(...(result.Users || []));
        marker = result.Marker;
      } while (marker);

      return users;
    });
  }

  private async checkMFA(user: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const username = user.UserName || 'Unknown';
    try {
      // Check if user has console login profile (console access)
      let hasConsoleAccess = false;
      try {
        await this.client.iam.send(new GetLoginProfileCommand({ UserName: username }));
        hasConsoleAccess = true;
      } catch {
        // User has no console access — MFA not required
      }

      if (hasConsoleAccess) {
        // Check actual MFA devices
        const mfaResult = await retry(async () => {
          return await this.client.iam.send(new ListMFADevicesCommand({ UserName: username }));
        });
        const mfaDevices = mfaResult.MFADevices ?? [];
        if (mfaDevices.length === 0) {
          findings.push(this.emit(
            'iam_user_mfa_enabled_console_access',
            { username, mfaDeviceCount: 0 },
            {
              message: `User "${username}" has console access but no MFA device is configured.`,
              remediation: `Enable MFA authentication for user "${username}" using an authenticator app or hardware token.`,
            }
          ));
        }
      }
    } catch (error) {
      logger.debug(`Failed to check MFA for ${username}`, { error: (error as Error).message });
    }
    return findings;
  }

  private async checkAccessKeys(username: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new ListAccessKeysCommand({ UserName: username });
        return await this.client.iam.send(cmd);
      });

      for (const key of result.AccessKeyMetadata || []) {
        const keyId = key.AccessKeyId || 'Unknown';
        const createDate = key.CreateDate?.getTime() || 0;
        const ageInDays = (Date.now() - createDate) / (1000 * 60 * 60 * 24);

        // Check key age
        if (ageInDays > 90) {
          findings.push(this.emit(
            'iam_rotate_access_key_90_days',
            { username, accessKeyId: keyId, ageInDays: Math.floor(ageInDays) },
            {
              message: `User "${username}" has an access key (${keyId}) that is ${Math.floor(ageInDays)} days old`,
              remediation: `Rotate access key ${keyId} for user "${username}"`,
            }
          ));
        }

        // Check if key is being used
        try {
          const lastUsed = await retry(async () => {
            const cmd = new GetAccessKeyLastUsedCommand({ AccessKeyId: keyId });
            return await this.client.iam.send(cmd);
          });

          const lastUsedDate = lastUsed.AccessKeyLastUsed?.LastUsedDate?.getTime() || 0;
          if (lastUsedDate === 0) {
            findings.push(this.emit(
              'iam_user_accesskey_never_used',
              { username, accessKeyId: keyId },
              {
                message: `User "${username}" has an access key (${keyId}) that has never been used`,
                remediation: `Delete unused access key ${keyId} for user "${username}"`,
              }
            ));
          } else {
            const daysSinceUsed = (Date.now() - lastUsedDate) / (1000 * 60 * 60 * 24);
            if (daysSinceUsed > 90) {
              findings.push(this.emit(
                'iam_user_accesskey_unused',
                { username, accessKeyId: keyId, daysSinceUsed: Math.floor(daysSinceUsed) },
                {
                  message: `User "${username}" has an access key (${keyId}) that hasn't been used for ${Math.floor(daysSinceUsed)} days`,
                  remediation: `Delete or review inactive access key ${keyId} for user "${username}"`,
                }
              ));
            }
          }
        } catch (error) {
          logger.debug(`Failed to check last used for key ${keyId}`, { error: (error as Error).message });
        }
      }

      if ((result.AccessKeyMetadata?.length || 0) > 2) {
        findings.push(this.emit(
          'iam_user_multiple_access_keys',
          { username, accessKeyCount: result.AccessKeyMetadata?.length },
          {
            message: `User "${username}" has ${result.AccessKeyMetadata?.length} access keys (should have maximum 2)`,
            remediation: `Review and delete unnecessary access keys for user "${username}"`,
          }
        ));
      }
    } catch (error) {
      logger.debug(`Failed to check access keys for ${username}`, { error: (error as Error).message });
    }

    return findings;
  }

  private async checkConsoleAccess(username: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await this.client.iam.send(new GetLoginProfileCommand({ UserName: username }));

      if (result.LoginProfile && !result.LoginProfile.CreateDate) {
        findings.push(this.emit(
          'iam_user_console_access_mfa_unverified',
          { username, hasLoginProfile: true },
          {
            message: `User "${username}" has console access but MFA status is unknown`,
            remediation: `Verify MFA is enabled for user "${username}" or disable console access`,
          }
        ));
      }
    } catch (error) {
      // Expected to fail for users without console access
      logger.debug(`User ${username} may not have console access`);
    }

    return findings;
  }

  private async checkInactiveUsers(user: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const username = user.UserName || 'Unknown';

    try {
      const passwordLastUsed = user.PasswordLastUsed?.getTime() || 0;
      const daysSinceLastUsed = (Date.now() - passwordLastUsed) / (1000 * 60 * 60 * 24);

      if (passwordLastUsed === 0) {
        findings.push(this.emit(
          'iam_user_never_logged_in',
          { username },
          {
            message: `User "${username}" has never logged in with password`,
            remediation: `Delete user "${username}" if no longer needed, or investigate setup`,
          }
        ));
      } else if (daysSinceLastUsed > 90) {
        findings.push(this.emit(
          'iam_user_console_access_unused',
          { username, daysSinceLastUsed: Math.floor(daysSinceLastUsed) },
          {
            message: `User "${username}" hasn't logged in for ${Math.floor(daysSinceLastUsed)} days`,
            remediation: `Review and remove inactive user "${username}" if no longer needed`,
          }
        ));
      }
    } catch (error) {
      logger.debug(`Failed to check inactive status for ${username}`, { error: (error as Error).message });
    }

    return findings;
  }

  private async checkPermissions(username: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new ListAttachedUserPoliciesCommand({ UserName: username });
        return await this.client.iam.send(cmd);
      });

      const attachedPolicies = result.AttachedPolicies || [];

      // Check for overly permissive policies
      for (const policy of attachedPolicies) {
        if (policy.PolicyName?.includes('PowerUser') || policy.PolicyName?.includes('Admin')) {
          findings.push(this.emit(
            'iam_user_overly_permissive_policy',
            { username, policy: policy.PolicyName },
            {
              message: `User "${username}" has policy "${policy.PolicyName}" which may grant excessive permissions`,
              remediation: `Review and replace with least-privilege policy for user "${username}"`,
            }
          ));
        }
      }

      if (attachedPolicies.length === 0) {
        findings.push(this.emit(
          'iam_user_no_policies_attached',
          { username },
          {
            message: `User "${username}" has no policies attached and cannot perform any actions`,
            remediation: `Attach appropriate policies to user "${username}" based on job requirements`,
          }
        ));
      }
    } catch (error) {
      logger.debug(`Failed to check permissions for ${username}`, { error: (error as Error).message });
    }

    return findings;
  }

  private async checkRootAccountViaReport(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      // Generate credential report
      await retry(async () => {
        await this.client.iam.send(new GenerateCredentialReportCommand({}));
      });
      // Wait briefly for report generation
      await new Promise(resolve => setTimeout(resolve, 2000));

      const reportResult = await retry(async () => {
        return await this.client.iam.send(new GetCredentialReportCommand({}));
      });

      if (!reportResult.Content) return findings;

      const csv = Buffer.from(reportResult.Content).toString('utf-8');
      const lines = csv.split('\n');
      const headers = lines[0].split(',');
      const rootLine = lines.find(l => l.startsWith('<root-account>') || l.startsWith('root'));
      if (!rootLine) return findings;

      const values = rootLine.split(',');
      const get = (col: string) => values[headers.indexOf(col)] ?? '';

      // CIS 1.4: Root access key exists
      if (get('access_key_1_active') === 'true' || get('access_key_2_active') === 'true') {
        findings.push(this.emit(
          'iam_no_root_access_key',
          { accessKey1Active: get('access_key_1_active'), accessKey2Active: get('access_key_2_active') },
          {
            message: 'The root account has active access keys. Root access keys should not exist.',
          }
        ));
      }

      // CIS 1.5: Root MFA not enabled
      if (get('mfa_active') === 'false') {
        findings.push(this.emit(
          'iam_root_mfa_enabled',
          { mfaActive: false },
          {
            message: 'Multi-factor authentication (MFA) is not enabled for the root account.',
          }
        ));
      }
    } catch (error) {
      logger.warn('Failed to generate/read credential report for root account check', { error: (error as Error).message });
      // Fallback: emit the original placeholder finding
      findings.push(this.emit(
        'iam_root_account_security_unverified',
        { status: 'requires-manual-check', error: (error as Error).message },
        {
          message: 'Unable to programmatically verify root account security. Manual verification required.',
        }
      ));
    }
    return findings;
  }

  private async checkPasswordPolicyDetails(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const result = await retry(async () => {
        return await this.client.iam.send(new GetAccountPasswordPolicyCommand({}));
      });
      const policy = result.PasswordPolicy;
      if (!policy) throw new Error('No password policy returned');

      // CIS 1.8: Minimum length 14
      if (!policy.MinimumPasswordLength || policy.MinimumPasswordLength < 14) {
        findings.push(this.emit(
          'iam_password_policy_minimum_length_14',
          { minimumLength: policy.MinimumPasswordLength },
          {
            message: `IAM password policy requires minimum length of ${policy.MinimumPasswordLength ?? 0}, but CIS requires at least 14 characters.`,
          }
        ));
      }

      // CIS 1.9: Password reuse prevention (24 passwords)
      if (!policy.PasswordReusePrevention || policy.PasswordReusePrevention < 24) {
        findings.push(this.emit(
          'iam_password_policy_reuse_24',
          { passwordReusePrevention: policy.PasswordReusePrevention },
          {
            message: `IAM password policy prevents reuse of only ${policy.PasswordReusePrevention ?? 0} previous passwords. CIS requires 24.`,
          }
        ));
      }
    } catch (error) {
      const msg = (error as Error).message;
      if (msg.includes('NoSuchEntity') || msg.includes('not exist')) {
        // No password policy set at all
        findings.push(this.emit(
          'iam_password_policy_not_configured',
          { status: 'no_policy' },
          {
            message: 'No IAM account password policy is configured. This allows weak passwords.',
          }
        ));
      } else {
        logger.warn('Failed to check password policy', { error: msg });
        findings.push(this.emit(
          'iam_password_policy_not_configured',
          { status: 'requires-manual-check' },
          {
            message: 'Unable to retrieve IAM password policy. Manual verification required.',
            remediation: 'Review password policy in AWS IAM console and ensure it enforces: minimum length 14, complexity, rotation, reuse prevention 24.',
            severity: 'MEDIUM',
          }
        ));
      }
    }
    return findings;
  }

  private async checkAccessAnalyzer(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const analyzerClient = new AccessAnalyzerClient({ region: this.client.getRegion() });
      const result = await retry(async () => {
        return await analyzerClient.send(new ListAnalyzersCommand({ type: 'ACCOUNT' }));
      });
      await analyzerClient.destroy();

      const activeAnalyzers = (result.analyzers ?? []).filter(a => a.status === 'ACTIVE');
      if (activeAnalyzers.length === 0) {
        findings.push(this.emit(
          'accessanalyzer_enabled',
          { analyzerCount: result.analyzers?.length ?? 0, activeCount: 0 },
          {
            message: 'IAM Access Analyzer is not enabled for this account. It helps identify resources shared with external entities.',
          }
        ));
      }
    } catch (error) {
      logger.debug('Failed to check IAM Access Analyzer', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkSupportRole(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      // List roles and check if any has AWSSupportAccess policy attached
      const roles: any[] = [];
      let marker: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.client.iam.send(new ListRolesCommand({ Marker: marker }));
        });
        roles.push(...(result.Roles ?? []));
        marker = result.Marker;
      } while (marker);

      // Was a sequential for-loop (one ListAttachedRolePolicies round-trip
      // per role, awaited one at a time) — on an account with hundreds of
      // roles that alone can take minutes with zero progress logged.
      const hasSupportFlags = await mapWithConcurrency(roles, 10, async role => {
        try {
          const attached = await retry(async () => {
            return await this.client.iam.send(new ListAttachedRolePoliciesCommand({ RoleName: role.RoleName! }));
          });
          return (attached.AttachedPolicies ?? []).some(
            p => p.PolicyArn === 'arn:aws:iam::aws:policy/AWSSupportAccess'
          );
        } catch (error) {
          logger.debug(`Failed to list attached policies for role ${role.RoleName}`, { error: (error as Error).message });
          return false;
        }
      });
      const supportRoleExists = hasSupportFlags.some(Boolean);

      if (!supportRoleExists) {
        findings.push(this.emit(
          'iam_support_role_created',
          { supportRoleExists: false },
          {
            message: 'No IAM role with AWSSupportAccess policy found. A dedicated support role is required by CIS to manage AWS support cases.',
          }
        ));
      }
    } catch (error) {
      logger.debug('Failed to check support role', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkUnassignedVirtualMFADevices(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const devices: any[] = [];
      let marker: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.client.iam.send(new ListVirtualMFADevicesCommand({ Marker: marker }));
        });
        devices.push(...(result.VirtualMFADevices ?? []));
        marker = result.Marker;
      } while (marker);

      const orphaned = devices.filter(d => !d.User);
      for (const device of orphaned) {
        findings.push(this.emit(
          'iam_virtual_mfa_device_unassigned',
          { serialNumber: device.SerialNumber, createDate: device.CreateDate },
          {
            message: `Virtual MFA device "${device.SerialNumber}" is not assigned to any IAM user.`,
            remediation: `Delete the unassigned virtual MFA device "${device.SerialNumber}" to reduce clutter and prevent reuse.`,
          }
        ));
      }
    } catch (error) {
      logger.debug('Failed to check virtual MFA devices', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkRoleInlinePolicies(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const roles: any[] = [];
      let marker: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.client.iam.send(new ListRolesCommand({ Marker: marker }));
        });
        roles.push(...(result.Roles ?? []));
        marker = result.Marker;
      } while (marker);

      const rolesToCheck = roles.filter(r => r.RoleName && !r.RoleName.startsWith('AWSServiceRoleFor'));

      // Was a sequential for-loop — same fix as checkSupportRole above.
      const perRoleFindings = await mapWithConcurrency(rolesToCheck, 10, async role => {
        const roleName = role.RoleName;
        try {
          const result = await retry(async () => {
            return await this.client.iam.send(new ListRolePoliciesCommand({ RoleName: roleName }));
          });
          const inlinePolicies = result.PolicyNames ?? [];
          if (inlinePolicies.length > 0) {
            return this.emit(
              'iam_role_has_inline_policies',
              { roleName, inlinePolicies },
              {
                message: `Role "${roleName}" has ${inlinePolicies.length} inline polic${inlinePolicies.length === 1 ? 'y' : 'ies'}: ${inlinePolicies.join(', ')}. Inline policies are harder to audit and reuse than managed policies.`,
                remediation: `Convert inline policies on role "${roleName}" to managed policies for better auditability and reuse.`,
              }
            );
          }
        } catch (error) {
          logger.debug(`Failed to list inline policies for role ${roleName}`, { error: (error as Error).message });
        }
        return null;
      });
      findings.push(...perRoleFindings.filter((f): f is ScanningResult => f !== null));
    } catch (error) {
      logger.debug('Failed to check role inline policies', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkWildcardPolicies(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      let marker: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.client.iam.send(new GetAccountAuthorizationDetailsCommand({
            Filter: ['LocalManagedPolicy'],
            Marker: marker,
          }));
        });

        for (const policy of result.Policies ?? []) {
          const policyName = policy.PolicyName ?? 'Unknown';
          const defaultVersion = policy.PolicyVersionList?.find(v => v.IsDefaultVersion);
          if (!defaultVersion?.Document) continue;

          try {
            const documentJson = typeof defaultVersion.Document === 'string'
              ? decodeURIComponent(defaultVersion.Document)
              : JSON.stringify(defaultVersion.Document);
            const document = typeof defaultVersion.Document === 'string'
              ? JSON.parse(documentJson)
              : defaultVersion.Document;

            const statements = Array.isArray(document.Statement) ? document.Statement : [document.Statement];
            for (const stmt of statements) {
              if (!stmt || stmt.Effect !== 'Allow') continue;
              const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
              const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
              const hasWildcardAction = actions.some((a: any) => a === '*');
              const hasWildcardResource = resources.some((r: any) => r === '*');

              if (hasWildcardAction && hasWildcardResource && (policy.AttachmentCount ?? 0) > 0) {
                findings.push(this.emit(
                  'iam_customer_attached_policy_no_administrative_privileges',
                  { policyName, policyArn: policy.Arn, attachmentCount: policy.AttachmentCount },
                  {
                    message: `Customer-managed policy "${policyName}" grants Allow on Action="*" and Resource="*" and is attached to ${policy.AttachmentCount} entit${policy.AttachmentCount === 1 ? 'y' : 'ies'}.`,
                    remediation: `Replace policy "${policyName}" with least-privilege policies scoped to required actions and resources.`,
                  }
                ));
                break;
              }
            }
          } catch (parseError) {
            logger.debug(`Failed to parse policy document for ${policyName}`, { error: (parseError as Error).message });
          }
        }

        marker = result.Marker;
      } while (marker);
    } catch (error) {
      logger.debug('Failed to check wildcard policies', { error: (error as Error).message });
    }
    return findings;
  }
}

export default IAMScanner;
