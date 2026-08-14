import { describe, it, expect, beforeEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';

import {
  CognitoIdentityProviderClient,
  ListUserPoolsCommand,
  DescribeUserPoolCommand,
  GetUserPoolMfaConfigCommand,
  DescribeRiskConfigurationCommand,
  ListUserPoolClientsCommand,
  DescribeUserPoolClientCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import {
  CognitoIdentityClient,
  ListIdentityPoolsCommand,
  DescribeIdentityPoolCommand,
  GetIdentityPoolRolesCommand,
} from '@aws-sdk/client-cognito-identity';
import { WAFV2Client, GetWebACLForResourceCommand } from '@aws-sdk/client-wafv2';

import CognitoScanner from '../../../src/scanners/cognito';
import type { ScanningResult } from '../../../src/utils/types';

const cognitoIdpMock = mockClient(CognitoIdentityProviderClient);
const cognitoIdentityMock = mockClient(CognitoIdentityClient);
const wafv2Mock = mockClient(WAFV2Client);

// Minimal AWSClient-shaped stub: CognitoScanner builds its own IDP/Identity
// SDK clients from getClientConfig(), but calls this.client.wafv2 directly
// for the WAF-attachment check, so a real WAFV2Client must be present too.
function makeAwsClient() {
  return {
    wafv2: new WAFV2Client({ region: 'us-east-1', credentials: {} }),
    getClientConfig: () => ({ region: 'us-east-1', credentials: { accessKeyId: 'x', secretAccessKey: 'y' } }),
  } as any;
}

function findByCheckId(findings: ScanningResult[], checkId: string): ScanningResult[] {
  return findings.filter((f) => f.checkId === checkId);
}

// A fully "good" user pool that should trip none of the per-pool findings,
// used as a baseline that individual tests deviate from.
const GOOD_POOL_DETAILS = {
  UserPool: {
    Id: 'us-east-1_good',
    Name: 'good-pool',
    DeletionProtection: 'ACTIVE',
    AdminCreateUserConfig: { AllowAdminCreateUserOnly: true },
    Policies: {
      PasswordPolicy: {
        MinimumLength: 14,
        TemporaryPasswordValidityDays: 7,
        RequireLowercase: true,
        RequireNumbers: true,
        RequireSymbols: true,
        RequireUppercase: true,
      },
    },
    UserPoolAddOns: { AdvancedSecurityMode: 'ENFORCED' },
  },
};

/** Default happy-path stubs so scan() doesn't throw/hang on unmocked calls. */
function stubDefaults() {
  cognitoIdpMock.on(ListUserPoolsCommand).resolves({ UserPools: [] });
  cognitoIdentityMock.on(ListIdentityPoolsCommand).resolves({ IdentityPools: [] });
  cognitoIdpMock.on(GetUserPoolMfaConfigCommand).resolves({ MfaConfiguration: 'ON' });
  cognitoIdpMock.on(DescribeRiskConfigurationCommand).resolves({
    RiskConfiguration: {
      CompromisedCredentialsRiskConfiguration: {
        EventFilter: ['SIGN_IN'],
        Actions: { EventAction: 'BLOCK' },
      },
      AccountTakeoverRiskConfiguration: {
        Actions: {
          LowAction: { EventAction: 'BLOCK' },
          MediumAction: { EventAction: 'BLOCK' },
          HighAction: { EventAction: 'BLOCK' },
        },
      },
    },
  });
  cognitoIdpMock.on(ListUserPoolClientsCommand).resolves({ UserPoolClients: [] });
  wafv2Mock.on(GetWebACLForResourceCommand).resolves({ WebACL: { Name: 'my-acl' } });
}

describe('CognitoScanner', () => {
  beforeEach(() => {
    cognitoIdpMock.reset();
    cognitoIdentityMock.reset();
    wafv2Mock.reset();
    stubDefaults();
  });

  describe('user pool baseline checks', () => {
    it('emits deletion-protection, self-registration, password-policy and advanced-security findings for a weak pool', async () => {
      cognitoIdpMock.on(ListUserPoolsCommand).resolves({
        UserPools: [{ Id: 'us-east-1_weak', Name: 'weak-pool' }],
      });
      cognitoIdpMock.on(DescribeUserPoolCommand).resolves({
        UserPool: {
          Id: 'us-east-1_weak',
          Name: 'weak-pool',
          DeletionProtection: 'INACTIVE',
          AdminCreateUserConfig: { AllowAdminCreateUserOnly: false },
          Policies: {
            PasswordPolicy: {
              MinimumLength: 8,
              TemporaryPasswordValidityDays: 14,
              RequireLowercase: false,
              RequireNumbers: false,
              RequireSymbols: false,
              RequireUppercase: false,
            },
          },
          UserPoolAddOns: { AdvancedSecurityMode: 'OFF' },
        },
      });

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      const deletionFindings = findByCheckId(findings, 'cognito_user_pool_deletion_protection_enabled');
      expect(deletionFindings).toHaveLength(1);
      expect(deletionFindings[0].service).toBe('Cognito');
      expect(deletionFindings[0].evidence).toMatchObject({
        userPoolId: 'us-east-1_weak',
        userPoolName: 'weak-pool',
        deletionProtection: 'INACTIVE',
      });

      expect(findByCheckId(findings, 'cognito_user_pool_self_registration_disabled')).toHaveLength(1);

      const minLengthFindings = findByCheckId(findings, 'cognito_user_pool_password_policy_minimum_length_14');
      expect(minLengthFindings).toHaveLength(1);
      expect(minLengthFindings[0].evidence).toMatchObject({ minimumLength: 8 });

      const tempPwFindings = findByCheckId(findings, 'cognito_user_pool_temporary_password_expiration');
      expect(tempPwFindings).toHaveLength(1);
      expect(tempPwFindings[0].evidence).toMatchObject({ temporaryPasswordValidityDays: 14 });

      expect(findByCheckId(findings, 'cognito_user_pool_advanced_security_enabled')).toHaveLength(1);

      // Table-driven password character-class checks: all four fire since all are false
      expect(findByCheckId(findings, 'cognito_user_pool_password_policy_lowercase')).toHaveLength(1);
      expect(findByCheckId(findings, 'cognito_user_pool_password_policy_number')).toHaveLength(1);
      expect(findByCheckId(findings, 'cognito_user_pool_password_policy_symbol')).toHaveLength(1);
      expect(findByCheckId(findings, 'cognito_user_pool_password_policy_uppercase')).toHaveLength(1);
    });

    it('emits no baseline findings for a fully hardened user pool', async () => {
      cognitoIdpMock.on(ListUserPoolsCommand).resolves({
        UserPools: [{ Id: 'us-east-1_good', Name: 'good-pool' }],
      });
      cognitoIdpMock.on(DescribeUserPoolCommand).resolves(GOOD_POOL_DETAILS);

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'cognito_user_pool_deletion_protection_enabled')).toHaveLength(0);
      expect(findByCheckId(findings, 'cognito_user_pool_self_registration_disabled')).toHaveLength(0);
      expect(findByCheckId(findings, 'cognito_user_pool_password_policy_minimum_length_14')).toHaveLength(0);
      expect(findByCheckId(findings, 'cognito_user_pool_temporary_password_expiration')).toHaveLength(0);
      expect(findByCheckId(findings, 'cognito_user_pool_advanced_security_enabled')).toHaveLength(0);
      expect(findByCheckId(findings, 'cognito_user_pool_password_policy_lowercase')).toHaveLength(0);
      expect(findByCheckId(findings, 'cognito_user_pool_password_policy_number')).toHaveLength(0);
      expect(findByCheckId(findings, 'cognito_user_pool_password_policy_symbol')).toHaveLength(0);
      expect(findByCheckId(findings, 'cognito_user_pool_password_policy_uppercase')).toHaveLength(0);
    });
  });

  describe('MFA and risk configuration', () => {
    it('emits cognito_user_pool_mfa_enabled when MFA is OFF', async () => {
      cognitoIdpMock.on(ListUserPoolsCommand).resolves({
        UserPools: [{ Id: 'us-east-1_good', Name: 'good-pool' }],
      });
      cognitoIdpMock.on(DescribeUserPoolCommand).resolves(GOOD_POOL_DETAILS);
      cognitoIdpMock.on(GetUserPoolMfaConfigCommand).resolves({ MfaConfiguration: 'OFF' });

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'cognito_user_pool_mfa_enabled');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ mfaConfiguration: 'OFF' });
    });

    it('does not emit risk-configuration findings when advanced security is ENFORCED and risk config blocks all levels', async () => {
      cognitoIdpMock.on(ListUserPoolsCommand).resolves({
        UserPools: [{ Id: 'us-east-1_good', Name: 'good-pool' }],
      });
      cognitoIdpMock.on(DescribeUserPoolCommand).resolves(GOOD_POOL_DETAILS);

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'cognito_user_pool_blocks_compromised_credentials_sign_in_attempts')).toHaveLength(0);
      expect(findByCheckId(findings, 'cognito_user_pool_blocks_potential_malicious_sign_in_attempts')).toHaveLength(0);
    });

    it('emits both risk-configuration findings when advanced security is ENFORCED but risk actions allow risk through', async () => {
      cognitoIdpMock.on(ListUserPoolsCommand).resolves({
        UserPools: [{ Id: 'us-east-1_good', Name: 'good-pool' }],
      });
      cognitoIdpMock.on(DescribeUserPoolCommand).resolves(GOOD_POOL_DETAILS);
      cognitoIdpMock.on(DescribeRiskConfigurationCommand).resolves({
        RiskConfiguration: {
          CompromisedCredentialsRiskConfiguration: {
            EventFilter: ['SIGN_IN'],
            Actions: { EventAction: 'NO_ACTION' },
          },
          AccountTakeoverRiskConfiguration: {
            Actions: {
              LowAction: { EventAction: 'NO_ACTION' },
              MediumAction: { EventAction: 'BLOCK' },
              HighAction: { EventAction: 'BLOCK' },
            },
          },
        },
      });

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      const compromisedFindings = findByCheckId(findings, 'cognito_user_pool_blocks_compromised_credentials_sign_in_attempts');
      expect(compromisedFindings).toHaveLength(1);
      expect(compromisedFindings[0].evidence).toMatchObject({
        compromisedCredentialsAction: 'NO_ACTION',
      });

      const takeoverFindings = findByCheckId(findings, 'cognito_user_pool_blocks_potential_malicious_sign_in_attempts');
      expect(takeoverFindings).toHaveLength(1);
      expect(takeoverFindings[0].evidence.accountTakeoverActions).toMatchObject({ low: 'NO_ACTION' });
    });

    it('skips DescribeRiskConfiguration and still flags both risk findings when advanced security is OFF', async () => {
      cognitoIdpMock.on(ListUserPoolsCommand).resolves({
        UserPools: [{ Id: 'us-east-1_off', Name: 'off-pool' }],
      });
      cognitoIdpMock.on(DescribeUserPoolCommand).resolves({
        UserPool: {
          ...GOOD_POOL_DETAILS.UserPool,
          Id: 'us-east-1_off',
          Name: 'off-pool',
          UserPoolAddOns: { AdvancedSecurityMode: 'OFF' },
        },
      });

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      expect(cognitoIdpMock.commandCalls(DescribeRiskConfigurationCommand)).toHaveLength(0);
      expect(findByCheckId(findings, 'cognito_user_pool_blocks_compromised_credentials_sign_in_attempts')).toHaveLength(1);
      expect(findByCheckId(findings, 'cognito_user_pool_blocks_potential_malicious_sign_in_attempts')).toHaveLength(1);
    });
  });

  describe('app client checks', () => {
    it('flags a client missing PreventUserExistenceErrors and token revocation', async () => {
      cognitoIdpMock.on(ListUserPoolsCommand).resolves({
        UserPools: [{ Id: 'us-east-1_good', Name: 'good-pool' }],
      });
      cognitoIdpMock.on(DescribeUserPoolCommand).resolves(GOOD_POOL_DETAILS);
      cognitoIdpMock.on(ListUserPoolClientsCommand).resolves({
        UserPoolClients: [{ ClientId: 'client-1', ClientName: 'web-app' }],
      });
      cognitoIdpMock.on(DescribeUserPoolClientCommand).resolves({
        UserPoolClient: {
          ClientId: 'client-1',
          ClientName: 'web-app',
          PreventUserExistenceErrors: 'LEGACY',
          EnableTokenRevocation: false,
        },
      });

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      const existenceFindings = findByCheckId(findings, 'cognito_user_pool_client_prevent_user_existence_errors');
      expect(existenceFindings).toHaveLength(1);
      expect(existenceFindings[0].evidence).toMatchObject({
        clientId: 'client-1',
        clientName: 'web-app',
        preventUserExistenceErrors: 'LEGACY',
      });

      const revocationFindings = findByCheckId(findings, 'cognito_user_pool_client_token_revocation_enabled');
      expect(revocationFindings).toHaveLength(1);
      expect(revocationFindings[0].evidence).toMatchObject({ clientId: 'client-1', enableTokenRevocation: false });
    });

    it('emits no client findings for a hardened app client', async () => {
      cognitoIdpMock.on(ListUserPoolsCommand).resolves({
        UserPools: [{ Id: 'us-east-1_good', Name: 'good-pool' }],
      });
      cognitoIdpMock.on(DescribeUserPoolCommand).resolves(GOOD_POOL_DETAILS);
      cognitoIdpMock.on(ListUserPoolClientsCommand).resolves({
        UserPoolClients: [{ ClientId: 'client-2', ClientName: 'hardened-app' }],
      });
      cognitoIdpMock.on(DescribeUserPoolClientCommand).resolves({
        UserPoolClient: {
          ClientId: 'client-2',
          ClientName: 'hardened-app',
          PreventUserExistenceErrors: 'ENABLED',
          EnableTokenRevocation: true,
        },
      });

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'cognito_user_pool_client_prevent_user_existence_errors')).toHaveLength(0);
      expect(findByCheckId(findings, 'cognito_user_pool_client_token_revocation_enabled')).toHaveLength(0);
    });

    it('paginates through ListUserPoolClients using NextToken and evaluates clients from every page', async () => {
      cognitoIdpMock.on(ListUserPoolsCommand).resolves({
        UserPools: [{ Id: 'us-east-1_good', Name: 'good-pool' }],
      });
      cognitoIdpMock.on(DescribeUserPoolCommand).resolves(GOOD_POOL_DETAILS);
      cognitoIdpMock
        .on(ListUserPoolClientsCommand)
        .resolvesOnce({ UserPoolClients: [{ ClientId: 'client-a', ClientName: 'app-a' }], NextToken: 'page2' })
        .resolvesOnce({ UserPoolClients: [{ ClientId: 'client-b', ClientName: 'app-b' }] });
      cognitoIdpMock.on(DescribeUserPoolClientCommand).resolves({
        UserPoolClient: { PreventUserExistenceErrors: 'LEGACY', EnableTokenRevocation: false },
      });

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      expect(cognitoIdpMock.commandCalls(ListUserPoolClientsCommand)).toHaveLength(2);
      const evaluatedClients = findByCheckId(findings, 'cognito_user_pool_client_token_revocation_enabled')
        .map((f: any) => f.evidence.clientId)
        .sort();
      expect(evaluatedClients).toEqual(['client-a', 'client-b']);
    });
  });

  describe('WAF ACL attachment', () => {
    it('emits cognito_user_pool_waf_acl_attached when no Web ACL is associated', async () => {
      cognitoIdpMock.on(ListUserPoolsCommand).resolves({
        UserPools: [{ Id: 'us-east-1_good', Name: 'good-pool' }],
      });
      cognitoIdpMock.on(DescribeUserPoolCommand).resolves(GOOD_POOL_DETAILS);
      wafv2Mock.on(GetWebACLForResourceCommand).resolves({ WebACL: undefined });

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'cognito_user_pool_waf_acl_attached');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ wafAclAttached: false });
    });

    it('does not emit the WAF finding when a Web ACL is attached', async () => {
      cognitoIdpMock.on(ListUserPoolsCommand).resolves({
        UserPools: [{ Id: 'us-east-1_good', Name: 'good-pool' }],
      });
      cognitoIdpMock.on(DescribeUserPoolCommand).resolves(GOOD_POOL_DETAILS);
      wafv2Mock.on(GetWebACLForResourceCommand).resolves({ WebACL: { Name: 'my-acl' } });

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'cognito_user_pool_waf_acl_attached')).toHaveLength(0);
    });
  });

  describe('identity pools', () => {
    it('flags an identity pool with guest access enabled, including the resolved unauthenticated role', async () => {
      cognitoIdentityMock.on(ListIdentityPoolsCommand).resolves({
        IdentityPools: [{ IdentityPoolId: 'pool-1', IdentityPoolName: 'my-identity-pool' }],
      });
      cognitoIdentityMock.on(DescribeIdentityPoolCommand).resolves({
        IdentityPoolId: 'pool-1',
        IdentityPoolName: 'my-identity-pool',
        AllowUnauthenticatedIdentities: true,
      });
      cognitoIdentityMock.on(GetIdentityPoolRolesCommand).resolves({
        Roles: { unauthenticated: 'arn:aws:iam::123456789012:role/guest-role' },
      });

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'cognito_identity_pool_guest_access_disabled');
      expect(matches).toHaveLength(1);
      expect(matches[0].service).toBe('Cognito');
      expect(matches[0].evidence).toMatchObject({
        identityPoolId: 'pool-1',
        identityPoolName: 'my-identity-pool',
        allowUnauthenticatedIdentities: true,
        unauthenticatedRole: 'arn:aws:iam::123456789012:role/guest-role',
      });
    });

    it('does not flag an identity pool with guest access disabled', async () => {
      cognitoIdentityMock.on(ListIdentityPoolsCommand).resolves({
        IdentityPools: [{ IdentityPoolId: 'pool-2', IdentityPoolName: 'locked-down-pool' }],
      });
      cognitoIdentityMock.on(DescribeIdentityPoolCommand).resolves({
        IdentityPoolId: 'pool-2',
        IdentityPoolName: 'locked-down-pool',
        AllowUnauthenticatedIdentities: false,
      });

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'cognito_identity_pool_guest_access_disabled')).toHaveLength(0);
      expect(cognitoIdentityMock.commandCalls(GetIdentityPoolRolesCommand)).toHaveLength(0);
    });

    it('paginates through ListIdentityPools using NextToken and evaluates pools from every page', async () => {
      cognitoIdentityMock
        .on(ListIdentityPoolsCommand)
        .resolvesOnce({ IdentityPools: [{ IdentityPoolId: 'pool-a', IdentityPoolName: 'a' }], NextToken: 'page2' })
        .resolvesOnce({ IdentityPools: [{ IdentityPoolId: 'pool-b', IdentityPoolName: 'b' }] });
      cognitoIdentityMock.on(DescribeIdentityPoolCommand).resolves({
        AllowUnauthenticatedIdentities: true,
      });

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      expect(cognitoIdentityMock.commandCalls(ListIdentityPoolsCommand)).toHaveLength(2);
      const evaluatedPools = findByCheckId(findings, 'cognito_identity_pool_guest_access_disabled')
        .map((f: any) => f.evidence.identityPoolId)
        .sort();
      expect(evaluatedPools).toEqual(['pool-a', 'pool-b']);
    });
  });

  describe('no-resources / empty account', () => {
    it('returns an empty findings array when there are no user pools and no identity pools', async () => {
      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });
  });

  describe('error handling', () => {
    it('does not throw and returns gracefully when ListUserPools fails on every retry', async () => {
      jest.useFakeTimers({ advanceTimers: true });
      cognitoIdpMock.on(ListUserPoolsCommand).rejects(new Error('AccessDenied'));

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      // The overall scan() try/catch swallows the error; identity pools still
      // never get a chance to run since listUserPools() throws inside the
      // outer try block before scanIdentityPools() is reached.
      expect(findings).toEqual([]);
      jest.useRealTimers();
    });

    it('skips a user pool whose DescribeUserPool call fails, without throwing', async () => {
      jest.useFakeTimers({ advanceTimers: true });
      cognitoIdpMock.on(ListUserPoolsCommand).resolves({
        UserPools: [{ Id: 'us-east-1_broken', Name: 'broken-pool' }],
      });
      cognitoIdpMock.on(DescribeUserPoolCommand).rejects(new Error('ResourceNotFoundException'));

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
      jest.useRealTimers();
    });

    it('continues scanning other clients when DescribeUserPoolClient fails for one client', async () => {
      jest.useFakeTimers({ advanceTimers: true });
      cognitoIdpMock.on(ListUserPoolsCommand).resolves({
        UserPools: [{ Id: 'us-east-1_good', Name: 'good-pool' }],
      });
      cognitoIdpMock.on(DescribeUserPoolCommand).resolves(GOOD_POOL_DETAILS);
      cognitoIdpMock.on(ListUserPoolClientsCommand).resolves({
        UserPoolClients: [
          { ClientId: 'broken-client', ClientName: 'broken-app' },
          { ClientId: 'fine-client', ClientName: 'fine-app' },
        ],
      });
      cognitoIdpMock
        .on(DescribeUserPoolClientCommand, { UserPoolId: 'us-east-1_good', ClientId: 'broken-client' } as any)
        .rejects(new Error('AccessDenied'));
      cognitoIdpMock
        .on(DescribeUserPoolClientCommand, { UserPoolId: 'us-east-1_good', ClientId: 'fine-client' } as any)
        .resolves({
          UserPoolClient: {
            ClientId: 'fine-client',
            ClientName: 'fine-app',
            PreventUserExistenceErrors: 'LEGACY',
            EnableTokenRevocation: false,
          },
        });

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'cognito_user_pool_client_token_revocation_enabled');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ clientId: 'fine-client' });
      jest.useRealTimers();
    });

    it('does not throw and still returns user pool findings when listing identity pools fails entirely', async () => {
      jest.useFakeTimers({ advanceTimers: true });
      cognitoIdpMock.on(ListUserPoolsCommand).resolves({
        UserPools: [{ Id: 'us-east-1_weak', Name: 'weak-pool' }],
      });
      cognitoIdpMock.on(DescribeUserPoolCommand).resolves({
        UserPool: {
          Id: 'us-east-1_weak',
          Name: 'weak-pool',
          DeletionProtection: 'INACTIVE',
        },
      });
      cognitoIdentityMock.on(ListIdentityPoolsCommand).rejects(new Error('ServiceUnavailable'));

      const scanner = new CognitoScanner(makeAwsClient());
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'cognito_user_pool_deletion_protection_enabled')).toHaveLength(1);
      expect(findByCheckId(findings, 'cognito_identity_pool_guest_access_disabled')).toHaveLength(0);
      jest.useRealTimers();
    });
  });
});
