import { describe, it, expect, beforeEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  SecretsManagerClient,
  ListSecretsCommand,
  DescribeSecretCommand,
  GetResourcePolicyCommand,
} from '@aws-sdk/client-secrets-manager';

import SecretsManagerScanner from '../../../src/scanners/secretsmanager';

// The scanner reaches AWS exclusively through `client.secretsmanager` (a
// pre-built SecretsManagerClient on the AWSClient wrapper) and `client.getAccountId()`.
const secretsManagerMock = mockClient(SecretsManagerClient);

function makeClient(accountId: string | null = '123456789012'): any {
  return {
    secretsmanager: new SecretsManagerClient({ region: 'us-east-1', credentials: { accessKeyId: 'x', secretAccessKey: 'y' } }),
    getClientConfig: () => ({ region: 'us-east-1', credentials: { accessKeyId: 'x', secretAccessKey: 'y' } }),
    getAccountId: async () => {
      if (accountId === null) throw new Error('cannot resolve account id');
      return accountId;
    },
  };
}

/** A DescribeSecret response that trips none of the hygiene checks (fully compliant secret). */
function compliantSecretDetails(overrides: Record<string, any> = {}) {
  return {
    Name: 'compliant-secret',
    ARN: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:compliant-secret-abc123',
    RotationEnabled: true,
    KmsKeyId: 'arn:aws:kms:us-east-1:123456789012:key/abcd-1234',
    ReplicationStatus: [{ Region: 'us-west-2', Status: 'InSync' }],
    LastRotatedDate: new Date(),
    LastAccessedDate: new Date(),
    ...overrides,
  };
}

describe('SecretsManagerScanner', () => {
  beforeEach(() => {
    secretsManagerMock.reset();
    // Default: no resource policy configured (NotFound), so validateResourcePolicy
    // short-circuits and returns [] unless a test overrides it.
    secretsManagerMock.on(GetResourcePolicyCommand).rejects({ name: 'ResourceNotFoundException' });
  });

  describe('scan()', () => {
    it('returns no findings when the account has no secrets', async () => {
      secretsManagerMock.on(ListSecretsCommand).resolves({ SecretList: [] });

      const scanner = new SecretsManagerScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });

    it('does not flag a fully-compliant secret with a restrictive resource policy on rotation, encryption, replication or usage', async () => {
      secretsManagerMock.on(ListSecretsCommand).resolves({
        SecretList: [{ Name: 'compliant-secret' }],
      });
      secretsManagerMock.on(DescribeSecretCommand).resolves(compliantSecretDetails());

      const restrictivePolicy = {
        Statement: [
          {
            Effect: 'Deny',
            Principal: '*',
            Action: 'secretsmanager:*',
            Condition: {
              StringNotEquals: {
                'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/AuthorizedRole',
              },
            },
          },
        ],
      };
      secretsManagerMock.on(GetResourcePolicyCommand).resolves({
        ResourcePolicy: JSON.stringify(restrictivePolicy),
      });

      const scanner = new SecretsManagerScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });

    it('flags a secret scheduled for deletion, without rotation, without a CMK, and without replication', async () => {
      secretsManagerMock.on(ListSecretsCommand).resolves({
        SecretList: [{ Name: 'stale-secret' }],
      });
      secretsManagerMock.on(DescribeSecretCommand).resolves({
        Name: 'stale-secret',
        ARN: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:stale-secret-abc123',
        DeletedDate: new Date(),
        RotationEnabled: false,
        KmsKeyId: undefined,
        ReplicationStatus: [],
        LastRotatedDate: undefined,
        LastAccessedDate: undefined,
      });

      const scanner = new SecretsManagerScanner(makeClient());
      const findings = await scanner.scan();

      const byCheckId = (id: string) => findings.find(f => f.checkId === id);

      const deletionFinding = byCheckId('secretsmanager_secret_scheduled_for_deletion');
      expect(deletionFinding).toBeDefined();
      expect(deletionFinding).toMatchObject({
        checkId: 'secretsmanager_secret_scheduled_for_deletion',
        service: 'SecretsManager',
      });
      expect(deletionFinding?.evidence).toMatchObject({ secretName: 'stale-secret' });

      expect(byCheckId('secretsmanager_automatic_rotation_enabled')).toBeDefined();
      expect(byCheckId('secretsmanager_secret_encrypted_with_cmk')).toBeDefined();
      expect(byCheckId('secretsmanager_secret_cross_region_replication')).toBeDefined();

      const rotatedFinding = byCheckId('secretsmanager_secret_rotated_periodically');
      expect(rotatedFinding).toBeDefined();
      expect(rotatedFinding?.evidence).toMatchObject({ secretName: 'stale-secret', lastRotatedDate: null });

      const unusedFinding = byCheckId('secretsmanager_secret_unused');
      expect(unusedFinding).toBeDefined();
      expect(unusedFinding?.evidence).toMatchObject({ secretName: 'stale-secret', lastAccessedDate: null });
    });

    it('flags a secret last rotated/accessed more than 90 days ago but not one rotated/accessed recently', async () => {
      const now = Date.now();
      const oldDate = new Date(now - 120 * 24 * 60 * 60 * 1000); // 120 days ago
      const recentDate = new Date(now - 5 * 24 * 60 * 60 * 1000); // 5 days ago

      secretsManagerMock.on(ListSecretsCommand).resolves({
        SecretList: [{ Name: 'old-secret' }, { Name: 'fresh-secret' }],
      });
      secretsManagerMock.on(DescribeSecretCommand, { SecretId: 'old-secret' }).resolves(
        compliantSecretDetails({ Name: 'old-secret', LastRotatedDate: oldDate, LastAccessedDate: oldDate })
      );
      secretsManagerMock.on(DescribeSecretCommand, { SecretId: 'fresh-secret' }).resolves(
        compliantSecretDetails({ Name: 'fresh-secret', LastRotatedDate: recentDate, LastAccessedDate: recentDate })
      );

      const scanner = new SecretsManagerScanner(makeClient());
      const findings = await scanner.scan();

      const oldRotated = findings.find(f => f.checkId === 'secretsmanager_secret_rotated_periodically' && f.evidence.secretName === 'old-secret');
      expect(oldRotated).toBeDefined();
      expect(oldRotated?.evidence).toMatchObject({ secretName: 'old-secret', daysSinceLastRotation: 120 });

      const oldUnused = findings.find(f => f.checkId === 'secretsmanager_secret_unused' && f.evidence.secretName === 'old-secret');
      expect(oldUnused).toBeDefined();
      expect(oldUnused?.evidence).toMatchObject({ secretName: 'old-secret', daysSinceLastAccess: 120 });

      expect(findings.some(f => f.checkId === 'secretsmanager_secret_rotated_periodically' && f.evidence.secretName === 'fresh-secret')).toBe(false);
      expect(findings.some(f => f.checkId === 'secretsmanager_secret_unused' && f.evidence.secretName === 'fresh-secret')).toBe(false);
    });

    it('flags a secret whose resource policy allows a wildcard principal without a restrictive condition as publicly accessible', async () => {
      secretsManagerMock.on(ListSecretsCommand).resolves({
        SecretList: [{ Name: 'public-secret' }],
      });
      secretsManagerMock.on(DescribeSecretCommand).resolves(
        compliantSecretDetails({ Name: 'public-secret', ARN: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:public-secret-abc123' })
      );
      secretsManagerMock.on(GetResourcePolicyCommand).resolves({
        ResourcePolicy: JSON.stringify({
          Statement: [{ Effect: 'Allow', Principal: '*', Action: 'secretsmanager:GetSecretValue' }],
        }),
      });

      const scanner = new SecretsManagerScanner(makeClient());
      const findings = await scanner.scan();

      const publicFinding = findings.find(f => f.checkId === 'secretsmanager_not_publicly_accessible');
      expect(publicFinding).toBeDefined();
      expect(publicFinding).toMatchObject({ checkId: 'secretsmanager_not_publicly_accessible', service: 'SecretsManager' });
      expect(publicFinding?.evidence).toMatchObject({ secretName: 'public-secret' });

      // A wildcard-principal-without-Deny policy also fails the restrictive-policy check.
      expect(findings.some(f => f.checkId === 'secretsmanager_has_restrictive_resource_policy')).toBe(true);
    });

    it('flags a secret with no resource-based policy at all as not meeting the restrictive-policy check', async () => {
      secretsManagerMock.on(ListSecretsCommand).resolves({
        SecretList: [{ Name: 'no-policy-secret' }],
      });
      secretsManagerMock.on(DescribeSecretCommand).resolves(compliantSecretDetails({ Name: 'no-policy-secret' }));
      // A successful call that carries no ResourcePolicy field is how "no policy attached"
      // is represented — as opposed to the call itself failing/being rejected, which the
      // scanner treats as "unreadable" and silently skips (see next test).
      secretsManagerMock.on(GetResourcePolicyCommand).resolves({});

      const scanner = new SecretsManagerScanner(makeClient());
      const findings = await scanner.scan();

      const restrictiveFinding = findings.find(f => f.checkId === 'secretsmanager_has_restrictive_resource_policy');
      expect(restrictiveFinding).toBeDefined();
      expect(restrictiveFinding?.evidence).toMatchObject({ secretName: 'no-policy-secret', policy: null });

      // Public-accessibility check is only evaluable when a policy exists.
      expect(findings.some(f => f.checkId === 'secretsmanager_not_publicly_accessible')).toBe(false);
    });

    it('skips both policy checks when GetResourcePolicyCommand rejects (policy unreadable, not absent)', async () => {
      secretsManagerMock.on(ListSecretsCommand).resolves({
        SecretList: [{ Name: 'unreadable-policy-secret' }],
      });
      secretsManagerMock.on(DescribeSecretCommand).resolves(compliantSecretDetails({ Name: 'unreadable-policy-secret' }));
      secretsManagerMock.on(GetResourcePolicyCommand).rejects({ name: 'ResourceNotFoundException' });

      const scanner = new SecretsManagerScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.checkId === 'secretsmanager_has_restrictive_resource_policy')).toBe(false);
      expect(findings.some(f => f.checkId === 'secretsmanager_not_publicly_accessible')).toBe(false);
    }, 15000);

    it('paginates through ListSecretsCommand using NextToken and scans every page', async () => {
      secretsManagerMock
        .on(ListSecretsCommand)
        .resolvesOnce({ SecretList: [{ Name: 'page1-secret' }], NextToken: 'token-2' })
        .resolvesOnce({ SecretList: [{ Name: 'page2-secret' }] });
      secretsManagerMock.on(DescribeSecretCommand, { SecretId: 'page1-secret' }).resolves(
        compliantSecretDetails({ Name: 'page1-secret', RotationEnabled: false })
      );
      secretsManagerMock.on(DescribeSecretCommand, { SecretId: 'page2-secret' }).resolves(
        compliantSecretDetails({ Name: 'page2-secret', RotationEnabled: false })
      );

      const scanner = new SecretsManagerScanner(makeClient());
      const findings = await scanner.scan();

      expect(secretsManagerMock.commandCalls(ListSecretsCommand)).toHaveLength(2);
      const flaggedSecrets = findings
        .filter(f => f.checkId === 'secretsmanager_automatic_rotation_enabled')
        .map(f => f.evidence.secretName)
        .sort();
      expect(flaggedSecrets).toEqual(['page1-secret', 'page2-secret']);
    });

    it('does not throw and returns gracefully when ListSecretsCommand fails repeatedly', async () => {
      secretsManagerMock.on(ListSecretsCommand).rejects(new Error('Access Denied'));

      const scanner = new SecretsManagerScanner(makeClient());
      await expect(scanner.scan()).resolves.toEqual([]);
    }, 15000);

    it('skips a secret whose DescribeSecretCommand fails, without throwing and without aborting the rest of the scan', async () => {
      secretsManagerMock.on(ListSecretsCommand).resolves({
        SecretList: [{ Name: 'broken-secret' }, { Name: 'ok-secret' }],
      });
      secretsManagerMock.on(DescribeSecretCommand, { SecretId: 'broken-secret' }).rejects(new Error('Throttled'));
      secretsManagerMock.on(DescribeSecretCommand, { SecretId: 'ok-secret' }).resolves(
        compliantSecretDetails({ Name: 'ok-secret', RotationEnabled: false })
      );

      const scanner = new SecretsManagerScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.evidence?.secretName === 'broken-secret')).toBe(false);
      const okFinding = findings.find(f => f.checkId === 'secretsmanager_automatic_rotation_enabled' && f.evidence.secretName === 'ok-secret');
      expect(okFinding).toBeDefined();
    }, 15000);
  });
});
