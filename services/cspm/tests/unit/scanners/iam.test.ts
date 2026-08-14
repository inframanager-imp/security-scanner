import { describe, it, expect, beforeEach, afterAll, afterEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  IAMClient,
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
import IAMScanner from '../../../src/scanners/iam';

// Minimal stand-in for AWSClient. IAMScanner reads `this.client.iam` directly
// (a pre-built IAMClient) and calls `this.client.getRegion()` for the
// AccessAnalyzer sub-check — see checkAccessAnalyzer() in src/scanners/iam.ts.
function makeMockAWSClient(iamClient: IAMClient) {
  return {
    iam: iamClient,
    getRegion: () => 'us-east-1',
    getClientConfig: () => ({ region: 'us-east-1', credentials: {} }),
  } as any;
}

const iamMock = mockClient(IAMClient);
const analyzerMock = mockClient(AccessAnalyzerClient);

/**
 * Stub out every IAM/AccessAnalyzer call the scan() orchestrator makes so
 * each test only needs to override the handful of calls relevant to the
 * scenario under test. Mirrors an account with zero users/roles/groups and
 * a fully-compliant password policy, credential report, etc., so tests that
 * override a subset of these still get a clean pass on everything else.
 */
function stubBaselineResponses() {
  iamMock.on(ListUsersCommand).resolves({ Users: [] });
  iamMock.on(ListRolesCommand).resolves({ Roles: [] });
  iamMock.on(ListGroupsCommand).resolves({ Groups: [] });
  iamMock.on(ListVirtualMFADevicesCommand).resolves({ VirtualMFADevices: [] });
  iamMock.on(ListServerCertificatesCommand).resolves({ ServerCertificateMetadataList: [] });
  iamMock.on(ListSAMLProvidersCommand).resolves({ SAMLProviderList: [{ Arn: 'arn:aws:iam::123456789012:saml-provider/Test' }] });
  iamMock.on(GetAccountPasswordPolicyCommand).resolves({
    PasswordPolicy: {
      MinimumPasswordLength: 14,
      PasswordReusePrevention: 24,
      RequireLowercaseCharacters: true,
      RequireUppercaseCharacters: true,
      RequireNumbers: true,
      RequireSymbols: true,
      MaxPasswordAge: 90,
    },
  });
  iamMock.on(GenerateCredentialReportCommand).resolves({});
  iamMock.on(GetCredentialReportCommand).resolves({
    Content: Buffer.from(
      'user,arn,mfa_active,password_enabled,password_last_used,password_last_changed,access_key_1_active,access_key_1_last_used_date,access_key_2_active,access_key_2_last_used_date\n' +
      '<root_account>,arn:aws:iam::123456789012:root,true,true,2026-08-01T00:00:00Z,2026-07-01T00:00:00Z,false,N/A,false,N/A\n'
    ),
  });
  iamMock.on(GetAccountAuthorizationDetailsCommand).resolves({
    Policies: [],
    UserDetailList: [],
    RoleDetailList: [],
    GroupDetailList: [],
  });
  analyzerMock.on(ListAnalyzersCommand).resolves({ analyzers: [{ name: 'default', status: 'ACTIVE' }] });
}

describe('IAMScanner', () => {
  beforeEach(() => {
    iamMock.reset();
    analyzerMock.reset();
    stubBaselineResponses();
    jest.useFakeTimers({ advanceTimers: true });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  afterAll(() => {
    iamMock.restore();
    analyzerMock.restore();
  });

  describe('scan()', () => {
    it('emits iam_user_mfa_enabled_console_access when a user has console access but no MFA device', async () => {
      iamMock.on(ListUsersCommand).resolves({
        Users: [{ UserName: 'alice', Arn: 'arn:aws:iam::123456789012:user/alice' }],
      });
      iamMock.on(GetLoginProfileCommand, { UserName: 'alice' }).resolves({
        LoginProfile: { UserName: 'alice', CreateDate: new Date('2026-01-01') },
      });
      iamMock.on(ListMFADevicesCommand, { UserName: 'alice' }).resolves({ MFADevices: [] });
      iamMock.on(ListAccessKeysCommand, { UserName: 'alice' }).resolves({ AccessKeyMetadata: [] });
      iamMock.on(ListAttachedUserPoliciesCommand, { UserName: 'alice' }).resolves({
        AttachedPolicies: [{ PolicyName: 'ReadOnlyAccess', PolicyArn: 'arn:aws:iam::aws:policy/ReadOnlyAccess' }],
      });

      const scanner = new IAMScanner(makeMockAWSClient(iamMock as unknown as IAMClient));
      const findings = await scanner.scan();

      const mfaFinding = findings.find(f => f.checkId === 'iam_user_mfa_enabled_console_access');
      expect(mfaFinding).toBeDefined();
      expect(mfaFinding?.service).toBe('IAM');
      expect(mfaFinding?.evidence).toMatchObject({ username: 'alice', mfaDeviceCount: 0 });
    }, 30000);

    it('does not emit iam_user_mfa_enabled_console_access when the user has an MFA device', async () => {
      iamMock.on(ListUsersCommand).resolves({
        Users: [{ UserName: 'bob', Arn: 'arn:aws:iam::123456789012:user/bob' }],
      });
      iamMock.on(GetLoginProfileCommand, { UserName: 'bob' }).resolves({
        LoginProfile: { UserName: 'bob', CreateDate: new Date('2026-01-01') },
      });
      iamMock.on(ListMFADevicesCommand, { UserName: 'bob' }).resolves({
        MFADevices: [{ SerialNumber: 'arn:aws:iam::123456789012:mfa/bob', UserName: 'bob' }],
      });
      iamMock.on(ListAccessKeysCommand, { UserName: 'bob' }).resolves({ AccessKeyMetadata: [] });
      iamMock.on(ListAttachedUserPoliciesCommand, { UserName: 'bob' }).resolves({
        AttachedPolicies: [{ PolicyName: 'ReadOnlyAccess', PolicyArn: 'arn:aws:iam::aws:policy/ReadOnlyAccess' }],
      });

      const scanner = new IAMScanner(makeMockAWSClient(iamMock as unknown as IAMClient));
      const findings = await scanner.scan();

      expect(findings.find(f => f.checkId === 'iam_user_mfa_enabled_console_access')).toBeUndefined();
    }, 30000);

    it('emits iam_rotate_access_key_90_days for an access key older than 90 days', async () => {
      const oldDate = new Date(Date.now() - 120 * 24 * 60 * 60 * 1000);
      iamMock.on(ListUsersCommand).resolves({
        Users: [{ UserName: 'carol', Arn: 'arn:aws:iam::123456789012:user/carol' }],
      });
      iamMock.on(GetLoginProfileCommand).rejects(new Error('NoSuchEntity'));
      iamMock.on(ListAccessKeysCommand, { UserName: 'carol' }).resolves({
        AccessKeyMetadata: [{ AccessKeyId: 'AKIAOLDKEY', Status: 'Active', CreateDate: oldDate }],
      });
      iamMock.on(GetAccessKeyLastUsedCommand, { AccessKeyId: 'AKIAOLDKEY' }).resolves({
        AccessKeyLastUsed: { LastUsedDate: new Date(), ServiceName: 's3', Region: 'us-east-1' },
      });
      iamMock.on(ListAttachedUserPoliciesCommand, { UserName: 'carol' }).resolves({
        AttachedPolicies: [{ PolicyName: 'ReadOnlyAccess', PolicyArn: 'arn:aws:iam::aws:policy/ReadOnlyAccess' }],
      });

      const scanner = new IAMScanner(makeMockAWSClient(iamMock as unknown as IAMClient));
      const findings = await scanner.scan();

      const keyFinding = findings.find(f => f.checkId === 'iam_rotate_access_key_90_days');
      expect(keyFinding).toBeDefined();
      expect(keyFinding?.checkId).toBe('iam_rotate_access_key_90_days');
      expect(keyFinding?.service).toBe('IAM');
      expect(keyFinding?.evidence).toMatchObject({ username: 'carol', accessKeyId: 'AKIAOLDKEY' });
      expect((keyFinding?.evidence as any).ageInDays).toBeGreaterThanOrEqual(90);
    }, 30000);

    it('returns no user-scoped findings when the account has no IAM users', async () => {
      // ListUsersCommand already stubbed to return [] via stubBaselineResponses().
      const scanner = new IAMScanner(makeMockAWSClient(iamMock as unknown as IAMClient));
      const findings = await scanner.scan();

      expect(findings.find(f => f.checkId === 'iam_user_mfa_enabled_console_access')).toBeUndefined();
      expect(findings.find(f => f.checkId === 'iam_rotate_access_key_90_days')).toBeUndefined();
      expect(findings.find(f => f.checkId === 'iam_user_access_inventory')).toBeUndefined();
    }, 30000);

    it('emits iam_no_root_access_key and iam_root_mfa_enabled from the credential report when root is insecure', async () => {
      // checkRootAccountViaReport() (which emits these two checkIds) matches
      // CSV rows starting with "<root-account>" (hyphen) — a different literal
      // than the "<root_account>" (underscore) prefix used by the other
      // credential-report-based checks in this scanner (checkAvoidRootUsage,
      // checkRootHardwareMFA, buildUserAccessInventory's `user` column match).
      iamMock.on(GetCredentialReportCommand).resolves({
        Content: Buffer.from(
          'user,arn,mfa_active,password_enabled,access_key_1_active,access_key_2_active\n' +
          '<root-account>,arn:aws:iam::123456789012:root,false,true,true,false\n'
        ),
      });

      const scanner = new IAMScanner(makeMockAWSClient(iamMock as unknown as IAMClient));
      const findings = await scanner.scan();

      const rootKeyFinding = findings.find(f => f.checkId === 'iam_no_root_access_key');
      const rootMfaFinding = findings.find(f => f.checkId === 'iam_root_mfa_enabled');
      expect(rootKeyFinding).toBeDefined();
      expect(rootKeyFinding?.service).toBe('IAM');
      expect(rootMfaFinding).toBeDefined();
      expect(rootMfaFinding?.service).toBe('IAM');
    }, 30000);

    it('emits iam_password_policy_not_configured when no password policy exists (NoSuchEntity)', async () => {
      iamMock.on(GetAccountPasswordPolicyCommand).rejects(new Error('NoSuchEntity: The Password Policy with domain name X cannot be found'));

      const scanner = new IAMScanner(makeMockAWSClient(iamMock as unknown as IAMClient));
      const findings = await scanner.scan();

      const finding = findings.find(f => f.checkId === 'iam_password_policy_not_configured');
      expect(finding).toBeDefined();
      expect(finding?.evidence).toMatchObject({ status: 'no_policy' });
    }, 30000);

    it('paginates ListRoles across multiple pages via the Marker token and processes roles from both pages', async () => {
      // scan() invokes several independent methods that each run their own
      // ListRoles Marker-pagination loop (checkSupportRole,
      // checkRoleInlinePolicies, checkRoleAdministratorAccess,
      // checkRoleAccessStaleness, checkSecurityAuditAndCloudShell). A
      // resolvesOnce/resolvesOnce chain would be drained entirely by the
      // first caller's loop, so page by the Marker value itself instead —
      // every method's pagination loop then sees the same deterministic
      // 2-page sequence.
      iamMock.on(ListRolesCommand, { Marker: undefined }).resolves({
        Roles: [{ RoleName: 'RoleAdminOne', Arn: 'arn:aws:iam::123456789012:role/RoleAdminOne' }],
        Marker: 'page-2-token',
      });
      iamMock.on(ListRolesCommand, { Marker: 'page-2-token' }).resolves({
        Roles: [{ RoleName: 'RoleAdminTwo', Arn: 'arn:aws:iam::123456789012:role/RoleAdminTwo' }],
      });

      iamMock.on(ListAttachedRolePoliciesCommand, { RoleName: 'RoleAdminOne' }).resolves({
        AttachedPolicies: [{ PolicyName: 'AdministratorAccess', PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' }],
      });
      iamMock.on(ListAttachedRolePoliciesCommand, { RoleName: 'RoleAdminTwo' }).resolves({
        AttachedPolicies: [{ PolicyName: 'AdministratorAccess', PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' }],
      });
      iamMock.on(ListRolePoliciesCommand).resolves({ PolicyNames: [] });

      const scanner = new IAMScanner(makeMockAWSClient(iamMock as unknown as IAMClient));
      const findings = await scanner.scan();

      const adminRoleFindings = findings.filter(f => f.checkId === 'iam_role_administratoraccess_policy');
      const roleNamesFlagged = adminRoleFindings.map(f => (f.evidence as any).roleName).sort();
      // checkRoleAdministratorAccess() is the only method that emits this
      // checkId, so seeing both role names here confirms its pagination loop
      // walked both the first page and the Marker-linked second page.
      expect(roleNamesFlagged).toEqual(['RoleAdminOne', 'RoleAdminTwo']);

      // Multiple scan() sub-methods paginate ListRoles independently (see
      // comment above), so the total call count is a multiple of the 2 pages
      // per full walk — assert it's at least 2 rather than an exact count.
      const callCount = iamMock.commandCalls(ListRolesCommand).length;
      expect(callCount).toBeGreaterThanOrEqual(2);
    }, 30000);

    it('does not throw and returns an array when an IAM SDK call rejects repeatedly', async () => {
      iamMock.on(ListUsersCommand).rejects(new Error('AccessDenied: not authorized to perform iam:ListUsers'));

      const scanner = new IAMScanner(makeMockAWSClient(iamMock as unknown as IAMClient));

      await expect(scanner.scan()).resolves.toEqual(expect.any(Array));
    }, 30000);

    it('emits iam_user_access_inventory with hasOpenEndedAccess=true for a user with AdministratorAccess', async () => {
      iamMock.on(GetAccountAuthorizationDetailsCommand).resolves({
        Policies: [],
        GroupDetailList: [],
        RoleDetailList: [],
        UserDetailList: [
          {
            UserName: 'dave',
            Arn: 'arn:aws:iam::123456789012:user/dave',
            GroupList: [],
            AttachedManagedPolicies: [
              { PolicyName: 'AdministratorAccess', PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' },
            ],
            UserPolicyList: [],
          },
        ],
      });
      iamMock.on(GetCredentialReportCommand).resolves({
        Content: Buffer.from(
          'user,mfa_active,password_enabled,password_last_changed,access_key_1_active,access_key_1_last_used_date,access_key_2_active,access_key_2_last_used_date\n' +
          'dave,true,true,2026-08-01,false,N/A,false,N/A\n' +
          '<root_account>,true,true,2026-08-01,false,N/A,false,N/A\n'
        ),
      });

      const scanner = new IAMScanner(makeMockAWSClient(iamMock as unknown as IAMClient));
      const findings = await scanner.scan();

      const inventoryFinding = findings.find(
        f => f.checkId === 'iam_user_access_inventory' && (f.evidence as any).userName === 'dave'
      );
      expect(inventoryFinding).toBeDefined();
      expect(inventoryFinding?.severity).toBe('HIGH');
      expect(inventoryFinding?.evidence).toMatchObject({ userName: 'dave', hasOpenEndedAccess: true });
    }, 30000);
  });
});
