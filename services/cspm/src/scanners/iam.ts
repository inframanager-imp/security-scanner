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
  ListGroupsCommand,
  ListServerCertificatesCommand,
  ListSAMLProvidersCommand,
  GenerateServiceLastAccessedDetailsCommand,
  GetServiceLastAccessedDetailsCommand,
} from '@aws-sdk/client-iam';
import { AccessAnalyzerClient, ListAnalyzersCommand } from '@aws-sdk/client-accessanalyzer';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import { CheckSeverity } from '../checks/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

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

      for (const user of users) {
        const username = user.UserName || 'Unknown';
        logger.debug(`Scanning user: ${username}`);

        // Check MFA
        const mfaFindings = await this.checkMFA(user);
        findings.push(...mfaFindings);

        // Check access keys
        const accessKeyFindings = await this.checkAccessKeys(username);
        findings.push(...accessKeyFindings);

        // Check console access
        const consoleFindings = await this.checkConsoleAccess(username);
        findings.push(...consoleFindings);

        // Check inactive users
        const inactiveFindings = await this.checkInactiveUsers(user);
        findings.push(...inactiveFindings);

        // Check excessive permissions
        const permissionFindings = await this.checkPermissions(username);
        findings.push(...permissionFindings);
      }

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

      // Check password policy complexity
      const passwordComplexityFindings = await this.checkPasswordPolicyComplexity();
      findings.push(...passwordComplexityFindings);

      // Check groups for admin access
      const groupAdminFindings = await this.checkGroupsForAdminAccess();
      findings.push(...groupAdminFindings);

      // Check root account usage
      const rootUsageFindings = await this.checkAvoidRootUsage();
      findings.push(...rootUsageFindings);

      // Check user hardware MFA
      const userMFAFindings = await this.checkUserHardwareMFA();
      findings.push(...userMFAFindings);

      // Check role administrator access
      const roleAdminFindings = await this.checkRoleAdministratorAccess();
      findings.push(...roleAdminFindings);

      // Check certificate expiration
      const certFindings = await this.checkCertificateExpiration();
      findings.push(...certFindings);

      // Check SAML providers
      const samlFindings = await this.checkSAMLProviders();
      findings.push(...samlFindings);

      // Check policies comprehensively (admin, escalation, service access, marketplace, etc.)
      const policiesFindings = await this.checkPoliciesComprehensive();
      findings.push(...policiesFindings);

      // Check role access staleness (bedrock)
      const roleAccessFindings = await this.checkRoleAccessStaleness();
      findings.push(...roleAccessFindings);

      // Check user credentials and access
      const userCredentialsFindings = await this.checkUserCredentialsAndAccess();
      findings.push(...userCredentialsFindings);

      // Check for security audit and CloudShell
      const auditFindings = await this.checkSecurityAuditAndCloudShell();
      findings.push(...auditFindings);

      // Check root hardware MFA
      const rootHwMfaFindings = await this.checkRootHardwareMFA();
      findings.push(...rootHwMfaFindings);

      // Check root credentials management
      const rootCredsFindings = await this.checkRootCredentialsManagement();
      findings.push(...rootCredsFindings);

      // Check user with temporary credentials
      const tempCredsFindings = await this.checkUserWithTemporaryCredentials();
      findings.push(...tempCredsFindings);

      // Consolidated per-user access inventory (powers the IAM Users table)
      const userInventoryFindings = await this.buildUserAccessInventory();
      findings.push(...userInventoryFindings);

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

      let supportRoleExists = false;
      for (const role of roles) {
        const attached = await retry(async () => {
          return await this.client.iam.send(new ListAttachedRolePoliciesCommand({ RoleName: role.RoleName! }));
        });
        const hasSupport = (attached.AttachedPolicies ?? []).some(
          p => p.PolicyArn === 'arn:aws:iam::aws:policy/AWSSupportAccess'
        );
        if (hasSupport) { supportRoleExists = true; break; }
      }

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

      for (const role of roles) {
        const roleName = role.RoleName;
        if (!roleName || roleName.startsWith('AWSServiceRoleFor')) continue;

        try {
          const result = await retry(async () => {
            return await this.client.iam.send(new ListRolePoliciesCommand({ RoleName: roleName }));
          });
          const inlinePolicies = result.PolicyNames ?? [];
          if (inlinePolicies.length > 0) {
            findings.push(this.emit(
              'iam_role_has_inline_policies',
              { roleName, inlinePolicies },
              {
                message: `Role "${roleName}" has ${inlinePolicies.length} inline polic${inlinePolicies.length === 1 ? 'y' : 'ies'}: ${inlinePolicies.join(', ')}. Inline policies are harder to audit and reuse than managed policies.`,
                remediation: `Convert inline policies on role "${roleName}" to managed policies for better auditability and reuse.`,
              }
            ));
          }
        } catch (error) {
          logger.debug(`Failed to list inline policies for role ${roleName}`, { error: (error as Error).message });
        }
      }
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

              if (hasWildcardAction && hasWildcardResource) {
                const attachmentCount = policy.AttachmentCount ?? 0;
                if (attachmentCount > 0) {
                  findings.push(this.emit(
                    'iam_customer_attached_policy_no_administrative_privileges',
                    { policyName, policyArn: policy.Arn, attachmentCount },
                    {
                      message: `Customer-managed policy "${policyName}" grants Allow on Action="*" and Resource="*" and is attached to ${attachmentCount} entit${attachmentCount === 1 ? 'y' : 'ies'}.`,
                      remediation: `Replace policy "${policyName}" with least-privilege policies scoped to required actions and resources.`,
                    }
                  ));
                } else {
                  findings.push(this.emit(
                    'iam_customer_unused_policy_administrative_privileges',
                    { policyName, policyArn: policy.Arn, attachmentCount },
                    {
                      message: `Customer-managed policy "${policyName}" grants Allow on Action="*" and Resource="*" and is not attached to any user, group, or role.`,
                    }
                  ));
                }
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

  private async checkPasswordPolicyComplexity(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const result = await retry(async () => {
        return await this.client.iam.send(new GetAccountPasswordPolicyCommand({}));
      });
      const policy = result.PasswordPolicy;
      if (!policy) return findings;

      const passwordPolicyChecks: Array<{checkId: string; value: boolean}> = [
        { checkId: 'iam_password_policy_lowercase', value: policy.RequireLowercaseCharacters ?? false },
        { checkId: 'iam_password_policy_uppercase', value: policy.RequireUppercaseCharacters ?? false },
        { checkId: 'iam_password_policy_number', value: policy.RequireNumbers ?? false },
        { checkId: 'iam_password_policy_symbol', value: policy.RequireSymbols ?? false },
      ];

      for (const check of passwordPolicyChecks) {
        if (!check.value) {
          findings.push(this.emit(check.checkId as any, { value: check.value }));
        }
      }

      if (!policy.MaxPasswordAge || policy.MaxPasswordAge > 90) {
        findings.push(this.emit('iam_password_policy_expires_passwords_within_90_days_or_less', { maxPasswordAge: policy.MaxPasswordAge }));
      }
    } catch (error) {
      logger.debug('Failed to check password policy complexity', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkGroupsForAdminAccess(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      let marker: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.client.iam.send(new ListGroupsCommand({ Marker: marker }));
        });

        for (const group of result.Groups ?? []) {
          const groupName = group.GroupName || 'Unknown';
          try {
            const attachedResult = await retry(async () => {
              return await this.client.iam.send(new ListAttachedUserPoliciesCommand({ UserName: groupName }));
            });

            for (const policy of attachedResult.AttachedPolicies ?? []) {
              if (policy.PolicyName === 'AdministratorAccess') {
                findings.push(this.emit('iam_group_administrator_access_policy', { groupName, policyName: policy.PolicyName }));
              }
            }
          } catch (error) {
            logger.debug(`Failed to check group ${groupName}`, { error: (error as Error).message });
          }
        }

        marker = result.Marker;
      } while (marker);
    } catch (error) {
      logger.debug('Failed to check groups', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkAvoidRootUsage(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      await retry(async () => {
        await this.client.iam.send(new GenerateCredentialReportCommand({}));
      });
      await new Promise(resolve => setTimeout(resolve, 2000));

      const reportResult = await retry(async () => {
        return await this.client.iam.send(new GetCredentialReportCommand({}));
      });

      if (!reportResult.Content) return findings;

      const csv = Buffer.from(reportResult.Content).toString('utf-8');
      const lines = csv.split('\n');
      const rootLine = lines.find(l => l.startsWith('<root_account>'));
      if (!rootLine) return findings;

      const headers = lines[0].split(',');
      const values = rootLine.split(',');
      const get = (col: string) => values[headers.indexOf(col)] ?? '';

      const passwordLastUsed = get('password_last_used');
      if (passwordLastUsed && passwordLastUsed !== 'N/A' && passwordLastUsed !== 'no_information') {
        const lastUsedDate = new Date(passwordLastUsed).getTime();
        const daysSinceUsed = (Date.now() - lastUsedDate) / (1000 * 60 * 60 * 24);
        if (daysSinceUsed <= 1) {
          findings.push(this.emit('iam_avoid_root_usage', { rootAccountUsed: true, daysSinceUsed }));
        }
      }
    } catch (error) {
      logger.debug('Failed to check root usage', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkUserHardwareMFA(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const users = await this.listAllUsers();
      for (const user of users) {
        const userName = user.UserName || 'Unknown';
        try {
          const mfaDevices = await retry(async () => {
            return await this.client.iam.send(new ListMFADevicesCommand({ UserName: userName }));
          });

          // Only flag the total absence of MFA. Any MFA device (virtual or
          // hardware) satisfies the control — requiring hardware specifically
          // is a stricter policy than this product enforces, and was firing
          // HIGH-severity findings for users who already have MFA enabled.
          if ((mfaDevices.MFADevices ?? []).length === 0) {
            findings.push(this.emit('iam_user_hardware_mfa_enabled', { userName, hasMFA: false }));
          }
        } catch (error) {
          logger.debug(`Failed to check MFA for ${userName}`, { error: (error as Error).message });
        }
      }
    } catch (error) {
      logger.debug('Failed to check user hardware MFA', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkRoleAdministratorAccess(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      let marker: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.client.iam.send(new ListRolesCommand({ Marker: marker }));
        });

        for (const role of result.Roles ?? []) {
          if (role.RoleName && !role.RoleName.startsWith('AWSServiceRoleFor')) {
            try {
              const attachedPolicies = await retry(async () => {
                return await this.client.iam.send(new ListAttachedRolePoliciesCommand({ RoleName: role.RoleName! }));
              });

              for (const policy of attachedPolicies.AttachedPolicies ?? []) {
                if (policy.PolicyName === 'AdministratorAccess') {
                  findings.push(this.emit('iam_role_administratoraccess_policy', { roleName: role.RoleName }));
                  break;
                }
              }
            } catch (error) {
              logger.debug(`Failed to check role ${role.RoleName}`, { error: (error as Error).message });
            }
          }
        }

        marker = result.Marker;
      } while (marker);
    } catch (error) {
      logger.debug('Failed to check role administrator access', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkCertificateExpiration(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const result = await retry(async () => {
        return await this.client.iam.send(new ListServerCertificatesCommand({}));
      });

      for (const cert of result.ServerCertificateMetadataList ?? []) {
        if (cert.Expiration && cert.Expiration.getTime() < Date.now()) {
          findings.push(this.emit('iam_no_expired_server_certificates_stored',
            { certificateName: cert.ServerCertificateName, expiration: cert.Expiration },
            { message: `Server certificate "${cert.ServerCertificateName}" expired on ${cert.Expiration.toISOString()}.` }
          ));
        }
      }
    } catch (error) {
      logger.debug('Failed to check certificate expiration', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkSAMLProviders(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const result = await retry(async () => {
        return await this.client.iam.send(new ListSAMLProvidersCommand({}));
      });

      if ((result.SAMLProviderList ?? []).length === 0) {
        findings.push(this.emit('iam_check_saml_providers_sts', { samlProviders: 0 }));
      }
    } catch (error) {
      logger.debug('Failed to check SAML providers', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkPoliciesComprehensive(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      let marker: string | undefined;
      do {
        const authDetailsResult = await retry(async () => {
          return await this.client.iam.send(new GetAccountAuthorizationDetailsCommand({
            Filter: ['LocalManagedPolicy', 'User', 'Role', 'Group'],
            Marker: marker,
          }));
        });

        // Check customer managed policies for various conditions
        for (const policy of authDetailsResult.Policies ?? []) {
          const policyName = policy.PolicyName ?? 'Unknown';
          const policyArn = policy.Arn ?? 'Unknown';
          const isAttached = (policy.AttachmentCount ?? 0) > 0;
          const isCustom = policy.Arn && policy.Arn.includes(':policy/');
          const defaultVersion = policy.PolicyVersionList?.find(v => v.IsDefaultVersion);
          if (!defaultVersion?.Document) continue;

          try {
            const document = this.parsePolicy(defaultVersion.Document);

            // Check for admin privileges
            if (this.checkPolicyForAdmin(document)) {
              if (isAttached && isCustom) {
                findings.push(this.emit('iam_customer_attached_policy_no_administrative_privileges',
                  { policyName, policyArn },
                  { message: `Customer policy "${policyName}" allows *:* and is attached.` }
                ));
              } else if (!isAttached && isCustom) {
                findings.push(this.emit('iam_customer_unattached_policy_no_administrative_privileges',
                  { policyName, policyArn },
                  { message: `Customer policy "${policyName}" allows *:* but is unattached.` }
                ));
              } else if (isAttached && !isCustom) {
                findings.push(this.emit('iam_aws_attached_policy_no_administrative_privileges',
                  { policyName, policyArn },
                  { message: `AWS managed policy "${policyName}" allows *:* and is attached.` }
                ));
              }
            }

            // Check for privilege escalation (custom policies only)
            if (isCustom) {
              const escalationActions = this.checkPolicyForPrivilegeEscalation(document);
              if (escalationActions.length > 0) {
                if (isAttached) {
                  findings.push(this.emit('iam_policy_allows_privilege_escalation',
                    { policyName, escalationActions },
                    { message: `Policy "${policyName}" allows privilege escalation: ${escalationActions.join(', ')}` }
                  ));
                }
              }
            }

            // Check for permissive role assumption
            if (isCustom) {
              if (this.checkPolicyForPermissiveAssumeRole(document)) {
                findings.push(this.emit('iam_no_custom_policy_permissive_role_assumption',
                  { policyName, policyArn },
                  { message: `Policy "${policyName}" allows sts:AssumeRole on wildcard resources.` }
                ));
              }
            }

            // Check for full service access
            if (this.checkPolicyForFullServiceAccess('cloudtrail', document)) {
              if (isCustom && isAttached) {
                findings.push(this.emit('iam_policy_no_full_access_to_cloudtrail',
                  { policyName, service: 'cloudtrail' }
                ));
              } else if (isCustom && !isAttached) {
                // Don't emit for unattached cloudtrail policies
              }
            }

            if (this.checkPolicyForFullServiceAccess('kms', document)) {
              if (isCustom && isAttached) {
                findings.push(this.emit('iam_policy_no_full_access_to_kms',
                  { policyName, service: 'kms' }
                ));
              }
            }

            if (this.checkPolicyForMarketplaceWildcard(document)) {
              if (isCustom && isAttached) {
                findings.push(this.emit('iam_policy_no_wildcard_marketplace_subscribe',
                  { policyName }
                ));
              }
            }
          } catch (parseError) {
            logger.debug(`Failed to parse policy ${policyName}`, { error: (parseError as Error).message });
          }
        }

        // Check users for policies and access keys
        for (const user of authDetailsResult.UserDetailList ?? []) {
          const userName = user.UserName || 'Unknown';

          // Check if user has direct policies attached
          if ((user.AttachedManagedPolicies?.length ?? 0) > 0 || (user.UserPolicyList?.length ?? 0) > 0) {
            for (const policy of user.AttachedManagedPolicies ?? []) {
              findings.push(this.emit('iam_policy_attached_only_to_group_or_roles',
                { userName, policyName: policy.PolicyName },
                { message: `User "${userName}" has attached policy "${policy.PolicyName}".` }
              ));
            }
            for (const policy of user.UserPolicyList ?? []) {
              findings.push(this.emit('iam_policy_attached_only_to_group_or_roles',
                { userName, policyName: policy.PolicyName },
                { message: `User "${userName}" has inline policy "${policy.PolicyName}".` }
              ));
            }
          }

          // Check user access keys
          if (user.UserName) {
            try {
              const accessKeys = await retry(async () => {
                return await this.client.iam.send(new ListAccessKeysCommand({ UserName: user.UserName! }));
              });
              const activeKeyCount = (accessKeys.AccessKeyMetadata ?? []).filter(k => k.Status === 'Active').length;
              if (activeKeyCount >= 2) {
                findings.push(this.emit('iam_user_two_active_access_key',
                  { userName, activeKeyCount },
                  { message: `User "${userName}" has ${activeKeyCount} active access keys.` }
                ));
              }
            } catch (error) {
              logger.debug(`Failed to check access keys for user ${userName}`, { error: (error as Error).message });
            }
          }
        }

        // Check roles for confused deputy prevention
        for (const role of authDetailsResult.RoleDetailList ?? []) {
          const roleName = role.RoleName || 'Unknown';
          if (role.AssumeRolePolicyDocument) {
            try {
              const trustPolicy = this.parsePolicy(role.AssumeRolePolicyDocument);
              if (this.isServiceRole(trustPolicy)) {
                if (!this.hasConfusedDeputyPrevention(trustPolicy)) {
                  findings.push(this.emit('iam_role_cross_service_confused_deputy_prevention',
                    { roleName },
                    { message: `Service role "${roleName}" lacks confused deputy prevention conditions.` }
                  ));
                }
              }
            } catch (error) {
              logger.debug(`Failed to check role trust policy for ${roleName}`, { error: (error as Error).message });
            }
          }

          // Check for ReadOnlyAccess on cross-account trusts
          for (const policy of role.AttachedManagedPolicies ?? []) {
            if (policy.PolicyName === 'ReadOnlyAccess') {
              if (role.AssumeRolePolicyDocument) {
                try {
                  const trustPolicy = this.parsePolicy(role.AssumeRolePolicyDocument);
                  if (this.hasExternalPrincipal(trustPolicy)) {
                    findings.push(this.emit('iam_role_cross_account_readonlyaccess_policy',
                      { roleName, policyName: policy.PolicyName },
                      { message: `Role "${roleName}" has ReadOnlyAccess and trusts external principals.` }
                    ));
                  }
                } catch (error) {
                  logger.debug(`Failed to check role ${roleName} for cross-account access`, { error: (error as Error).message });
                }
              }
            }
          }

          // Check inline policies on roles
          for (const policy of role.RolePolicyList ?? []) {
            const policyName = policy.PolicyName || 'Unknown';
            if (policy.PolicyDocument) {
              try {
                const document = this.parsePolicy(policy.PolicyDocument);

                const escalationActions = this.checkPolicyForPrivilegeEscalation(document);
                if (escalationActions.length > 0) {
                  findings.push(this.emit('iam_inline_policy_allows_privilege_escalation',
                    { roleName, policyName, escalationActions },
                    { message: `Inline policy on role "${roleName}" allows escalation.` }
                  ));
                }

                if (this.checkPolicyForAdmin(document)) {
                  findings.push(this.emit('iam_inline_policy_no_administrative_privileges',
                    { roleName, policyName },
                    { message: `Inline policy on role "${roleName}" allows *:*.` }
                  ));
                }

                if (this.checkPolicyForFullServiceAccess('cloudtrail', document)) {
                  findings.push(this.emit('iam_inline_policy_no_full_access_to_cloudtrail',
                    { roleName, policyName, service: 'cloudtrail' }
                  ));
                }

                if (this.checkPolicyForFullServiceAccess('kms', document)) {
                  findings.push(this.emit('iam_inline_policy_no_full_access_to_kms',
                    { roleName, policyName, service: 'kms' }
                  ));
                }

                if (this.checkPolicyForMarketplaceWildcard(document)) {
                  findings.push(this.emit('iam_inline_policy_no_wildcard_marketplace_subscribe',
                    { roleName, policyName }
                  ));
                }
              } catch (error) {
                logger.debug(`Failed to parse inline policy ${policyName} on role ${roleName}`, { error: (error as Error).message });
              }
            }
          }
        }

        marker = authDetailsResult.Marker;
      } while (marker);
    } catch (error) {
      logger.debug('Failed to check policies comprehensively', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkRoleAccessStaleness(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      let marker: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.client.iam.send(new ListRolesCommand({ Marker: marker }));
        });

        for (const role of result.Roles ?? []) {
          if (role.Arn) {
            try {
              const details = await retry(async () => {
                return await this.client.iam.send(
                  new GenerateServiceLastAccessedDetailsCommand({ Arn: role.Arn! })
                );
              });

              const response = await retry(async () => {
                return await this.client.iam.send(
                  new GetServiceLastAccessedDetailsCommand({ JobId: details.JobId! })
                );
              });

              for (const service of response.ServicesLastAccessed ?? []) {
                if (service.ServiceNamespace === 'bedrock') {
                  if (!service.LastAuthenticated) {
                    findings.push(this.emit('iam_role_access_not_stale_to_bedrock',
                      { roleName: role.RoleName, service: 'bedrock', neverUsed: true }
                    ));
                  } else {
                    const daysSinceUsed = (Date.now() - service.LastAuthenticated.getTime()) / (1000 * 60 * 60 * 24);
                    if (daysSinceUsed > 60) {
                      findings.push(this.emit('iam_role_access_not_stale_to_bedrock',
                        { roleName: role.RoleName, service: 'bedrock', daysSinceUsed }
                      ));
                    }
                  }
                }
              }
            } catch (error) {
              logger.debug(`Failed to check access staleness for role ${role.RoleName}`, { error: (error as Error).message });
            }
          }
        }

        marker = result.Marker;
      } while (marker);
    } catch (error) {
      logger.debug('Failed to check role access staleness', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkUserCredentialsAndAccess(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      let marker: string | undefined;
      do {
        const authDetailsResult = await retry(async () => {
          return await this.client.iam.send(new GetAccountAuthorizationDetailsCommand({
            Filter: ['User'],
            Marker: marker,
          }));
        });

        for (const user of authDetailsResult.UserDetailList ?? []) {
          const userName = user.UserName || 'Unknown';
          if (!user.UserName) continue;

          // Check for never-used access keys (setup initial key check)
          try {
            const accessKeys = await retry(async () => {
              return await this.client.iam.send(new ListAccessKeysCommand({ UserName: user.UserName! }));
            });
            const keys = accessKeys.AccessKeyMetadata ?? [];
            for (const key of keys) {
              if (key.Status === 'Active' && !keys.some(k => k.AccessKeyId !== key.AccessKeyId)) {
                findings.push(this.emit('iam_user_no_setup_initial_access_key',
                  { userName, accessKeyId: key.AccessKeyId, neverUsed: true },
                  { message: `User "${userName}" has a never-used access key.` }
                ));
              }
            }
          } catch (error) {
            logger.debug(`Failed to check initial access key for user ${userName}`, { error: (error as Error).message });
          }
        }

        marker = authDetailsResult.Marker;
      } while (marker);
    } catch (error) {
      logger.debug('Failed to check user credentials', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkSecurityAuditAndCloudShell(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      let marker: string | undefined;
      let hasSecurityAuditRole = false;

      do {
        const result = await retry(async () => {
          return await this.client.iam.send(new ListRolesCommand({ Marker: marker }));
        });

        for (const role of result.Roles ?? []) {
          if (role.RoleName) {
            try {
              const attachedPolicies = await retry(async () => {
                return await this.client.iam.send(new ListAttachedRolePoliciesCommand({ RoleName: role.RoleName! }));
              });

              for (const policy of attachedPolicies.AttachedPolicies ?? []) {
                if (policy.PolicyName === 'SecurityAudit') {
                  hasSecurityAuditRole = true;
                }
                if (policy.PolicyName === 'AWSCloudShellFullAccess') {
                  findings.push(this.emit('iam_policy_cloudshell_admin_not_attached',
                    { roleName: role.RoleName, policyName: policy.PolicyName },
                    { message: `Role "${role.RoleName}" has CloudShell full access.` }
                  ));
                }
              }
            } catch (error) {
              logger.debug(`Failed to check role ${role.RoleName}`, { error: (error as Error).message });
            }
          }
        }

        marker = result.Marker;
      } while (marker);

      if (!hasSecurityAuditRole) {
        findings.push(this.emit('iam_securityaudit_role_created', { hasSecurityAuditRole: false }));
      }
    } catch (error) {
      logger.debug('Failed to check security audit and CloudShell', { error: (error as Error).message });
    }
    return findings;
  }

  private parsePolicy(doc: any): any {
    if (typeof doc === 'string') {
      return JSON.parse(decodeURIComponent(doc));
    }
    return doc;
  }

  private checkPolicyForAdmin(document: any): boolean {
    try {
      const statements = Array.isArray(document.Statement) ? document.Statement : [document.Statement];
      for (const stmt of statements) {
        if (stmt.Effect !== 'Allow') continue;
        const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
        const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
        const hasWildcardAction = actions.some((a: any) => a === '*');
        const hasWildcardResource = resources.some((r: any) => r === '*');
        if (hasWildcardAction && hasWildcardResource) return true;
      }
    } catch (error) {
      logger.debug('Failed to check policy for admin access', { error: (error as Error).message });
    }
    return false;
  }

  private checkPolicyForPrivilegeEscalation(document: any): string[] {
    const escalationActions = [
      'iam:PassRole', 'iam:AddUserToGroup', 'iam:AttachUserPolicy', 'iam:PutUserPolicy',
      'iam:CreateAccessKey', 'iam:CreateLoginProfile', 'iam:UpdateAssumeRolePolicy',
      'iam:AttachRolePolicy', 'iam:PutRolePolicy', 'sts:AssumeRole',
    ];
    const affected: string[] = [];
    try {
      const statements = Array.isArray(document.Statement) ? document.Statement : [document.Statement];
      for (const stmt of statements) {
        if (stmt.Effect !== 'Allow') continue;
        const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
        for (const action of actions) {
          if (escalationActions.includes(action) || action === '*' || action === 'iam:*') {
            affected.push(action);
          }
        }
      }
    } catch (error) {
      logger.debug('Failed to check policy for escalation', { error: (error as Error).message });
    }
    return affected;
  }

  private checkPolicyForPermissiveAssumeRole(document: any): boolean {
    try {
      const statements = Array.isArray(document.Statement) ? document.Statement : [document.Statement];
      for (const stmt of statements) {
        if (stmt.Effect !== 'Allow') continue;
        const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
        const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
        const hasAssumeRole = actions.some((a: any) => ['sts:AssumeRole', 'sts:*', '*'].includes(a));
        const hasWildcardResource = resources.some((r: any) => r === '*');
        if (hasAssumeRole && hasWildcardResource) return true;
      }
    } catch (error) {
      logger.debug('Failed to check for permissive AssumeRole', { error: (error as Error).message });
    }
    return false;
  }

  private checkPolicyForFullServiceAccess(serviceName: string, document: any): boolean {
    try {
      const statements = Array.isArray(document.Statement) ? document.Statement : [document.Statement];
      for (const stmt of statements) {
        if (stmt.Effect !== 'Allow') continue;
        const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
        for (const action of actions) {
          if (action === '*' || action === `${serviceName}:*`) {
            return true;
          }
        }
      }
    } catch (error) {
      logger.debug(`Failed to check for ${serviceName} full access`, { error: (error as Error).message });
    }
    return false;
  }

  private checkPolicyForMarketplaceWildcard(document: any): boolean {
    try {
      const statements = Array.isArray(document.Statement) ? document.Statement : [document.Statement];
      for (const stmt of statements) {
        if (stmt.Effect !== 'Allow') continue;
        const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
        const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];
        const hasMarketplaceAction = actions.some((a: any) => a === '*' || a === 'aws-marketplace:*' || a === 'aws-marketplace:Subscribe');
        const hasWildcardResource = resources.some((r: any) => r === '*');
        if (hasMarketplaceAction && hasWildcardResource) return true;
      }
    } catch (error) {
      logger.debug('Failed to check for marketplace wildcard', { error: (error as Error).message });
    }
    return false;
  }

  private isServiceRole(trustPolicy: any): boolean {
    try {
      const statements = Array.isArray(trustPolicy.Statement) ? trustPolicy.Statement : [trustPolicy.Statement];
      for (const stmt of statements) {
        if (stmt.Effect === 'Allow' && stmt.Principal?.Service) {
          return true;
        }
      }
    } catch (error) {
      logger.debug('Failed to check if service role', { error: (error as Error).message });
    }
    return false;
  }

  private hasConfusedDeputyPrevention(trustPolicy: any): boolean {
    try {
      const statements = Array.isArray(trustPolicy.Statement) ? trustPolicy.Statement : [trustPolicy.Statement];
      for (const stmt of statements) {
        if (stmt.Condition?.StringEquals?.['aws:SourceAccount'] || stmt.Condition?.StringEquals?.['aws:SourceArn']) {
          return true;
        }
      }
    } catch (error) {
      logger.debug('Failed to check confused deputy prevention', { error: (error as Error).message });
    }
    return false;
  }

  private hasExternalPrincipal(trustPolicy: any): boolean {
    try {
      const statements = Array.isArray(trustPolicy.Statement) ? trustPolicy.Statement : [trustPolicy.Statement];
      for (const stmt of statements) {
        if (stmt.Effect === 'Allow') {
          const principals = stmt.Principal?.AWS || [];
          const principalList = Array.isArray(principals) ? principals : [principals];
          for (const principal of principalList) {
            if (typeof principal === 'string' && principal === '*') return true;
            if (typeof principal === 'string' && !principal.includes(':root')) return true;
          }
        }
      }
    } catch (error) {
      logger.debug('Failed to check external principal', { error: (error as Error).message });
    }
    return false;
  }

  private async checkRootHardwareMFA(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      await retry(async () => {
        await this.client.iam.send(new GenerateCredentialReportCommand({}));
      });
      await new Promise(resolve => setTimeout(resolve, 2000));

      const reportResult = await retry(async () => {
        return await this.client.iam.send(new GetCredentialReportCommand({}));
      });

      if (!reportResult.Content) return findings;

      const csv = Buffer.from(reportResult.Content).toString('utf-8');
      const lines = csv.split('\n');
      const rootLine = lines.find(l => l.startsWith('<root_account>'));
      if (!rootLine) return findings;

      const headers = lines[0].split(',');
      const values = rootLine.split(',');
      const get = (col: string) => values[headers.indexOf(col)] ?? '';

      // Only flag the total absence of MFA on the root account. Any active
      // MFA (virtual or hardware) satisfies the control — see the matching
      // comment on checkUserHardwareMFA() above for why hardware-specific
      // enforcement was removed.
      const mfaActive = get('mfa_active') === 'true';
      if (!mfaActive) {
        findings.push(this.emit('iam_root_hardware_mfa_enabled', { mfaActive: false }));
      }
    } catch (error) {
      logger.debug('Failed to check root hardware MFA', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkRootCredentialsManagement(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      // Note: This check typically requires AWS Organizations API which is separate.
      // For now, we'll emit a finding but note that proper implementation requires organizations client.
      findings.push(this.emit('iam_root_credentials_management_enabled',
        { feature: 'RootCredentialsManagement', status: 'unverified' },
        { message: 'Unable to verify root credentials management status. Requires AWS Organizations API.' }
      ));
    } catch (error) {
      logger.debug('Failed to check root credentials management', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkUserWithTemporaryCredentials(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const users = await this.listAllUsers();
      for (const user of users) {
        if (user.UserName) {
          try {
            const details = await retry(async () => {
              return await this.client.iam.send(
                new GenerateServiceLastAccessedDetailsCommand({ Arn: user.Arn! })
              );
            });

            const response = await retry(async () => {
              return await this.client.iam.send(
                new GetServiceLastAccessedDetailsCommand({ JobId: details.JobId! })
              );
            });

            const accessedServices = response.ServicesLastAccessed ?? [];
            const nonIamStsServices = accessedServices.filter(
              s => !['iam', 'sts'].includes(s.ServiceNamespace ?? '')
            );

            if (nonIamStsServices.length > 0) {
              const accessKeys = await retry(async () => {
                return await this.client.iam.send(new ListAccessKeysCommand({ UserName: user.UserName! }));
              });

              const hasAccessKeys = (accessKeys.AccessKeyMetadata?.length ?? 0) > 0;
              if (hasAccessKeys) {
                findings.push(this.emit('iam_user_with_temporary_credentials',
                  { userName: user.UserName, hasAccessKeys: true, usesNonIamSts: true },
                  { message: `User "${user.UserName}" has long-lived credentials and uses services other than IAM/STS.` }
                ));
              }
            }
          } catch (error) {
            logger.debug(`Failed to check temporary credentials for user ${user.UserName}`, { error: (error as Error).message });
          }
        }
      }
    } catch (error) {
      logger.debug('Failed to check user temporary credentials', { error: (error as Error).message });
    }
    return findings;
  }

  /**
   * One consolidated record per IAM user: effective permissions (groups +
   * attached/inline policies), roles they can assume, and access hygiene
   * (MFA, password age, access key age). Powers the dedicated "IAM Users"
   * table in the UI — that view reads this checkId's evidence rather than
   * re-deriving it from the narrower single-purpose checks above.
   *
   * Built from three account-wide calls (not per-user loops):
   *   - GetAccountAuthorizationDetails (Filter=User,Group,Role,LocalManagedPolicy)
   *     returns every user/group/role's policy attachments AND documents in
   *     one paginated call.
   *   - The credential report gives MFA/password/access-key age for every
   *     user in one call.
   */
  private async buildUserAccessInventory(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const userDetails: any[] = [];
      const groupDetails: any[] = [];
      const roleDetails: any[] = [];
      const managedPolicies: any[] = [];
      let marker: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.client.iam.send(new GetAccountAuthorizationDetailsCommand({
            Filter: ['User', 'Group', 'Role', 'LocalManagedPolicy'],
            Marker: marker,
          }));
        });
        userDetails.push(...(result.UserDetailList ?? []));
        groupDetails.push(...(result.GroupDetailList ?? []));
        roleDetails.push(...(result.RoleDetailList ?? []));
        managedPolicies.push(...(result.Policies ?? []));
        marker = result.Marker;
      } while (marker);

      // Customer-managed policy ARN -> is it admin-equivalent (Action:* + Resource:*)?
      const managedPolicyAdmin = new Map<string, boolean>();
      for (const p of managedPolicies) {
        const defaultVersion = p.PolicyVersionList?.find((v: any) => v.IsDefaultVersion);
        let isAdmin = false;
        if (defaultVersion?.Document) {
          try {
            isAdmin = this.checkPolicyForAdmin(this.parsePolicy(defaultVersion.Document));
          } catch (e) {
            logger.debug(`Failed to parse policy document for ${p.PolicyName}`, { error: (e as Error).message });
          }
        }
        if (p.Arn) managedPolicyAdmin.set(p.Arn, isAdmin);
      }
      const isAdminEquivalentAttached = (attached: { PolicyArn?: string }): boolean =>
        attached.PolicyArn === 'arn:aws:iam::aws:policy/AdministratorAccess'
        || (attached.PolicyArn ? managedPolicyAdmin.get(attached.PolicyArn) ?? false : false);
      const isAdminEquivalentInline = (inline: { PolicyDocument?: string }): boolean => {
        if (!inline.PolicyDocument) return false;
        try {
          return this.checkPolicyForAdmin(this.parsePolicy(inline.PolicyDocument));
        } catch {
          return false;
        }
      };

      const groupByName = new Map<string, any>();
      for (const g of groupDetails) if (g.GroupName) groupByName.set(g.GroupName, g);

      // Per role: is it admin-equivalent, and which principals can assume it?
      const roleAdmin = new Map<string, boolean>();
      const roleAssumableBy = new Map<string, { explicit: Set<string>; wildcard: boolean }>();
      for (const r of roleDetails) {
        if (!r.RoleName) continue;
        const attachedAdmin = (r.AttachedManagedPolicies ?? []).some((ap: any) => isAdminEquivalentAttached(ap));
        const inlineAdmin = (r.RolePolicyList ?? []).some((ip: any) => isAdminEquivalentInline(ip));
        roleAdmin.set(r.RoleName, attachedAdmin || inlineAdmin);

        const principals = { explicit: new Set<string>(), wildcard: false };
        try {
          const trust = this.parsePolicy(r.AssumeRolePolicyDocument);
          const statements = Array.isArray(trust.Statement) ? trust.Statement : [trust.Statement];
          for (const stmt of statements) {
            if (!stmt || stmt.Effect !== 'Allow') continue;
            const awsPrincipals = stmt.Principal?.AWS;
            const list = Array.isArray(awsPrincipals) ? awsPrincipals : awsPrincipals ? [awsPrincipals] : [];
            for (const p of list) {
              if (p === '*') principals.wildcard = true;
              else principals.explicit.add(p);
            }
          }
        } catch (e) {
          logger.debug(`Failed to parse trust policy for role ${r.RoleName}`, { error: (e as Error).message });
        }
        roleAssumableBy.set(r.RoleName, principals);
      }

      // Credential report — MFA/password/access-key data for every user in one call.
      const credRows = new Map<string, Record<string, string>>();
      try {
        await retry(async () => {
          await this.client.iam.send(new GenerateCredentialReportCommand({}));
        });
        await new Promise(resolve => setTimeout(resolve, 2000));
        const reportResult = await retry(async () => {
          return await this.client.iam.send(new GetCredentialReportCommand({}));
        });
        if (reportResult.Content) {
          const csv = Buffer.from(reportResult.Content).toString('utf-8');
          const lines = csv.split('\n').filter(Boolean);
          const headers = lines[0].split(',');
          for (const line of lines.slice(1)) {
            const values = line.split(',');
            const row: Record<string, string> = {};
            headers.forEach((h, i) => { row[h] = values[i] ?? ''; });
            if (row.user) credRows.set(row.user, row);
          }
        }
      } catch (error) {
        logger.debug('Failed to fetch credential report for user inventory', { error: (error as Error).message });
      }

      const daysSince = (dateStr?: string): number | null => {
        if (!dateStr || dateStr === 'N/A' || dateStr === 'not_supported' || dateStr === 'no_information') return null;
        const t = new Date(dateStr).getTime();
        if (Number.isNaN(t)) return null;
        return Math.floor((Date.now() - t) / (1000 * 60 * 60 * 24));
      };

      for (const user of userDetails) {
        const userName = user.UserName;
        if (!userName) continue;
        const userArn = user.Arn ?? '';

        const directPolicies = [
          ...(user.AttachedManagedPolicies ?? []).map((ap: any) => ({
            name: ap.PolicyName ?? 'Unknown', type: 'managed' as const, isAdminEquivalent: isAdminEquivalentAttached(ap),
          })),
          ...(user.UserPolicyList ?? []).map((ip: any) => ({
            name: ip.PolicyName ?? 'Unknown', type: 'inline' as const, isAdminEquivalent: isAdminEquivalentInline(ip),
          })),
        ];

        const groups: string[] = user.GroupList ?? [];
        const groupPolicies = groups.flatMap(groupName => {
          const g = groupByName.get(groupName);
          if (!g) return [];
          return [
            ...(g.AttachedManagedPolicies ?? []).map((ap: any) => ({
              groupName, policyName: ap.PolicyName ?? 'Unknown', type: 'managed' as const, isAdminEquivalent: isAdminEquivalentAttached(ap),
            })),
            ...(g.GroupPolicyList ?? []).map((ip: any) => ({
              groupName, policyName: ip.PolicyName ?? 'Unknown', type: 'inline' as const, isAdminEquivalent: isAdminEquivalentInline(ip),
            })),
          ];
        });

        const assumableRoles = roleDetails
          .filter((r: any) => r.RoleName)
          .map((r: any) => {
            const assumable = roleAssumableBy.get(r.RoleName);
            if (!assumable) return null;
            if (assumable.wildcard) {
              return { roleName: r.RoleName, isAdminEquivalent: roleAdmin.get(r.RoleName) ?? false, assumableBy: 'wildcard' as const };
            }
            if (assumable.explicit.has(userArn)) {
              return { roleName: r.RoleName, isAdminEquivalent: roleAdmin.get(r.RoleName) ?? false, assumableBy: 'explicit' as const };
            }
            return null;
          })
          .filter((x): x is { roleName: string; isAdminEquivalent: boolean; assumableBy: 'explicit' | 'wildcard' } => x !== null);

        const hasOpenEndedAccess =
          directPolicies.some(p => p.isAdminEquivalent) ||
          groupPolicies.some(p => p.isAdminEquivalent) ||
          assumableRoles.some(r => r.isAdminEquivalent);

        const cred = credRows.get(userName);
        const mfaEnabled = cred?.mfa_active === 'true';
        const passwordEnabled = cred?.password_enabled === 'true';
        const passwordAgeDays = passwordEnabled ? daysSince(cred?.password_last_changed) : null;

        const key1Active = cred?.access_key_1_active === 'true';
        const key2Active = cred?.access_key_2_active === 'true';
        const key1Age = key1Active ? daysSince(cred?.access_key_1_last_used_date) : null;
        const key2Age = key2Active ? daysSince(cred?.access_key_2_last_used_date) : null;
        const accessKeysActive = [key1Active, key2Active].filter(Boolean).length;
        // A never-used active key (no last-used date at all) is treated as
        // maximally stale, matching how checkAccessKeys() elsewhere in this
        // file treats lastUsedDate === 0.
        const hasNeverUsedActiveKey = (key1Active && !cred?.access_key_1_last_used_date) || (key2Active && !cred?.access_key_2_last_used_date);
        const keyAges = [key1Age, key2Age].filter((a): a is number => a !== null);
        const accessKeyAgeDays = keyAges.length > 0 ? Math.min(...keyAges) : null;

        const mfaMissing = !mfaEnabled;
        const passwordStale = passwordAgeDays !== null && passwordAgeDays > 30;
        const keyStale = (accessKeyAgeDays !== null && accessKeyAgeDays > 30) || hasNeverUsedActiveKey;

        const hasHygieneIssue = mfaMissing || passwordStale || keyStale;
        const severity: CheckSeverity = hasOpenEndedAccess ? 'HIGH' : hasHygieneIssue ? 'MEDIUM' : 'INFO';

        const issueParts: string[] = [];
        if (hasOpenEndedAccess) issueParts.push('open-ended (admin-equivalent) access');
        if (mfaMissing) issueParts.push('MFA not enabled');
        if (passwordStale) issueParts.push(`password not changed in ${passwordAgeDays}+ days`);
        if (keyStale) issueParts.push(hasNeverUsedActiveKey ? 'active access key never used' : `access key unused for ${accessKeyAgeDays}+ days`);

        findings.push(this.emit('iam_user_access_inventory', {
          userName, arn: userArn,
          groups, directPolicies, groupPolicies, assumableRoles,
          hasOpenEndedAccess,
          mfaEnabled, mfaMissing,
          passwordEnabled, passwordAgeDays, passwordStale,
          accessKeysActive, accessKeyAgeDays, keyStale, hasNeverUsedActiveKey,
        }, {
          severity,
          message: issueParts.length > 0
            ? `IAM user "${userName}": ${issueParts.join('; ')}.`
            : `IAM user "${userName}" has no outstanding access-hygiene issues.`,
        }));
      }
    } catch (error) {
      logger.debug('Failed to build user access inventory', { error: (error as Error).message });
    }
    return findings;
  }
}

export default IAMScanner;
