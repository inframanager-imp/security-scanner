import { describe, it, expect, beforeEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';

import {
  KMSClient,
  ListKeysCommand,
  DescribeKeyCommand,
  GetKeyRotationStatusCommand,
  GetKeyPolicyCommand,
  ListResourceTagsCommand,
  ListAliasesCommand,
} from '@aws-sdk/client-kms';

import KMSScanner from '../../../src/scanners/kms';
import type { ScanningResult } from '../../../src/utils/types';

const kmsMock = mockClient(KMSClient);

// Minimal AWSClient-shaped stub: KMSScanner reads client.kms directly (unlike
// scanners that build their own SDK client via getClientConfig()), so the stub
// exposes a `kms` property pointing at the mocked KMSClient instance.
const fakeAwsClient: any = {
  kms: new KMSClient({ region: 'us-east-1', credentials: { accessKeyId: 'x', secretAccessKey: 'y' } as any }),
  getClientConfig: () => ({ region: 'us-east-1', credentials: { accessKeyId: 'x', secretAccessKey: 'y' } }),
};

function findByCheckId(findings: ScanningResult[], checkId: string): ScanningResult[] {
  return findings.filter((f) => f.checkId === checkId);
}

// Defaults so scan() doesn't throw/hang on unmocked calls: every command used
// by the scanner gets a benign empty-ish response unless a test overrides it.
function setBenignDefaults(): void {
  kmsMock.on(ListAliasesCommand).resolves({ Aliases: [] });
  kmsMock.on(ListKeysCommand).resolves({ Keys: [] });
  kmsMock.on(ListResourceTagsCommand).resolves({ Tags: [] });
}

describe('KMSScanner', () => {
  beforeEach(() => {
    kmsMock.reset();
    setBenignDefaults();
  });

  describe('key state checks', () => {
    it('emits kms_cmk_not_deleted_unintentionally for a key pending deletion', async () => {
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-1' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: { KeyId: 'key-1', KeyState: 'PendingDeletion', KeyManager: 'CUSTOMER' },
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'kms_cmk_not_deleted_unintentionally');
      expect(matches).toHaveLength(1);
      expect(matches[0].service).toBe('KMS');
      expect(matches[0].evidence).toMatchObject({ keyId: 'key-1', state: 'PendingDeletion' });
    });

    it('emits kms_cmk_are_used for a disabled key', async () => {
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-2' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: { KeyId: 'key-2', KeyState: 'Disabled', KeyManager: 'CUSTOMER' },
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'kms_cmk_are_used');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ keyId: 'key-2', state: 'Disabled' });
    });

    it('emits no state findings for an enabled, non-deleted key', async () => {
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-3' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: { KeyId: 'key-3', KeyState: 'Enabled', KeyManager: 'AWS' },
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'kms_cmk_not_deleted_unintentionally')).toHaveLength(0);
      expect(findByCheckId(findings, 'kms_cmk_are_used')).toHaveLength(0);
    });
  });

  describe('rotation check', () => {
    it('emits kms_cmk_rotation_enabled when a customer-managed key has rotation disabled', async () => {
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-4' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: { KeyId: 'key-4', KeyState: 'Enabled', KeyManager: 'CUSTOMER', MultiRegion: false },
      });
      kmsMock.on(GetKeyRotationStatusCommand).resolves({ KeyRotationEnabled: false });
      kmsMock.on(GetKeyPolicyCommand).resolves({
        Policy: JSON.stringify({ Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::123456789012:root' } }] }),
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'kms_cmk_rotation_enabled');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ keyId: 'key-4', rotationEnabled: false });
    });

    it('does not emit kms_cmk_rotation_enabled when rotation is enabled', async () => {
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-5' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: { KeyId: 'key-5', KeyState: 'Enabled', KeyManager: 'CUSTOMER', MultiRegion: false },
      });
      kmsMock.on(GetKeyRotationStatusCommand).resolves({ KeyRotationEnabled: true });
      kmsMock.on(GetKeyPolicyCommand).resolves({
        Policy: JSON.stringify({ Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::123456789012:root' } }] }),
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'kms_cmk_rotation_enabled')).toHaveLength(0);
    });

    it('does not check rotation for AWS-managed keys', async () => {
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-6' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: { KeyId: 'key-6', KeyState: 'Enabled', KeyManager: 'AWS' },
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'kms_cmk_rotation_enabled')).toHaveLength(0);
      expect(kmsMock.commandCalls(GetKeyRotationStatusCommand)).toHaveLength(0);
    });
  });

  describe('multi-region and public accessibility checks', () => {
    it('emits kms_cmk_not_multi_region for an enabled multi-region customer-managed key', async () => {
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-7' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: { KeyId: 'key-7', KeyState: 'Enabled', KeyManager: 'CUSTOMER', MultiRegion: true },
      });
      kmsMock.on(GetKeyRotationStatusCommand).resolves({ KeyRotationEnabled: true });
      kmsMock.on(GetKeyPolicyCommand).resolves({
        Policy: JSON.stringify({ Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::123456789012:root' } }] }),
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'kms_cmk_not_multi_region');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ keyId: 'key-7', multiRegion: true });
    });

    it('emits kms_key_not_publicly_accessible when the key policy allows a wildcard principal without a restrictive condition', async () => {
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-8' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: { KeyId: 'key-8', KeyState: 'Enabled', KeyManager: 'CUSTOMER', MultiRegion: false },
      });
      kmsMock.on(GetKeyRotationStatusCommand).resolves({ KeyRotationEnabled: true });
      kmsMock.on(GetKeyPolicyCommand).resolves({
        Policy: JSON.stringify({
          Statement: [{ Effect: 'Allow', Principal: '*', Action: 'kms:*' }],
        }),
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'kms_key_not_publicly_accessible');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ keyId: 'key-8', publicPrincipal: true });
    });

    it('does not emit kms_key_not_publicly_accessible when the wildcard principal has a restrictive condition', async () => {
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-9' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: { KeyId: 'key-9', KeyState: 'Enabled', KeyManager: 'CUSTOMER', MultiRegion: false },
      });
      kmsMock.on(GetKeyRotationStatusCommand).resolves({ KeyRotationEnabled: true });
      kmsMock.on(GetKeyPolicyCommand).resolves({
        Policy: JSON.stringify({
          Statement: [{
            Effect: 'Allow',
            Principal: '*',
            Action: 'kms:Decrypt',
            Condition: { StringEquals: { 'aws:PrincipalAccount': '123456789012' } },
          }],
        }),
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'kms_key_not_publicly_accessible')).toHaveLength(0);
    });
  });

  describe('Nitro Enclave attestation checks', () => {
    it('emits kms_key_enclave_attestation_not_enforced when a sensitive Allow lacks any attestation condition', async () => {
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-10' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: {
          KeyId: 'key-10',
          KeyState: 'Enabled',
          KeyManager: 'CUSTOMER',
          MultiRegion: false,
          Description: 'enclave signing key',
        },
      });
      kmsMock.on(GetKeyRotationStatusCommand).resolves({ KeyRotationEnabled: true });
      kmsMock.on(GetKeyPolicyCommand).resolves({
        Policy: JSON.stringify({
          Statement: [{
            Sid: 'AllowDecrypt',
            Effect: 'Allow',
            Principal: { AWS: 'arn:aws:iam::123456789012:role/enclave-role' },
            Action: 'kms:Decrypt',
          }],
        }),
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'kms_key_enclave_attestation_not_enforced');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ keyId: 'key-10', sid: 'AllowDecrypt' });

      // Bypassable-path check should also fire since nothing is attestation-bound.
      expect(findByCheckId(findings, 'kms_key_enclave_attestation_bypassable_path')).toHaveLength(1);
    });

    it('emits kms_key_enclave_attestation_no_deployment_binding when attested but missing deployment-context binding', async () => {
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-11' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: {
          KeyId: 'key-11',
          KeyState: 'Enabled',
          KeyManager: 'CUSTOMER',
          MultiRegion: false,
          Description: 'enclave key',
        },
      });
      kmsMock.on(GetKeyRotationStatusCommand).resolves({ KeyRotationEnabled: true });
      kmsMock.on(GetKeyPolicyCommand).resolves({
        Policy: JSON.stringify({
          Statement: [{
            Sid: 'AttestedOnly',
            Effect: 'Allow',
            Principal: { AWS: 'arn:aws:iam::123456789012:role/enclave-role' },
            Action: 'kms:Decrypt',
            Condition: {
              StringEqualsIgnoreCase: { 'kms:RecipientAttestation:PCR0': 'abc123' },
            },
          }],
        }),
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'kms_key_enclave_attestation_not_enforced')).toHaveLength(0);
      expect(findByCheckId(findings, 'kms_key_enclave_attestation_bypassable_path')).toHaveLength(0);
      const matches = findByCheckId(findings, 'kms_key_enclave_attestation_no_deployment_binding');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ keyId: 'key-11', statementsWithoutBinding: ['AttestedOnly'] });
    });

    it('emits no enclave findings for a fully attested and deployment-bound policy', async () => {
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-12' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: {
          KeyId: 'key-12',
          KeyState: 'Enabled',
          KeyManager: 'CUSTOMER',
          MultiRegion: false,
          Description: 'enclave key fully bound',
        },
      });
      kmsMock.on(GetKeyRotationStatusCommand).resolves({ KeyRotationEnabled: true });
      kmsMock.on(GetKeyPolicyCommand).resolves({
        Policy: JSON.stringify({
          Statement: [{
            Sid: 'FullyBound',
            Effect: 'Allow',
            Principal: { AWS: 'arn:aws:iam::123456789012:role/enclave-role' },
            Action: 'kms:Decrypt',
            Condition: {
              StringEqualsIgnoreCase: {
                'kms:RecipientAttestation:PCR0': 'abc123',
                'kms:RecipientAttestation:PCR3': 'role-hash',
              },
            },
          }],
        }),
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'kms_key_enclave_attestation_not_enforced')).toHaveLength(0);
      expect(findByCheckId(findings, 'kms_key_enclave_attestation_bypassable_path')).toHaveLength(0);
      expect(findByCheckId(findings, 'kms_key_enclave_attestation_no_deployment_binding')).toHaveLength(0);
    });

    it('does not evaluate enclave checks for a key with no enclave signal', async () => {
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-13' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: {
          KeyId: 'key-13',
          KeyState: 'Enabled',
          KeyManager: 'CUSTOMER',
          MultiRegion: false,
          Description: 'plain application key',
        },
      });
      kmsMock.on(GetKeyRotationStatusCommand).resolves({ KeyRotationEnabled: true });
      kmsMock.on(GetKeyPolicyCommand).resolves({
        Policy: JSON.stringify({
          Statement: [{
            Sid: 'PlainAllow',
            Effect: 'Allow',
            Principal: { AWS: 'arn:aws:iam::123456789012:role/app-role' },
            Action: 'kms:Decrypt',
          }],
        }),
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'kms_key_enclave_attestation_not_enforced')).toHaveLength(0);
      expect(findByCheckId(findings, 'kms_key_enclave_attestation_bypassable_path')).toHaveLength(0);
      expect(findByCheckId(findings, 'kms_key_enclave_attestation_no_deployment_binding')).toHaveLength(0);
    });
  });

  describe('no-resources / empty account', () => {
    it('returns no findings when the account has no KMS keys', async () => {
      kmsMock.on(ListKeysCommand).resolves({ Keys: [] });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });
  });

  describe('pagination', () => {
    it('paginates through ListKeys using Marker/NextMarker and scans every page', async () => {
      kmsMock
        .on(ListKeysCommand)
        .resolvesOnce({ Keys: [{ KeyId: 'page1-key' }], NextMarker: 'marker-2' })
        .resolvesOnce({ Keys: [{ KeyId: 'page2-key' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: { KeyId: 'irrelevant', KeyState: 'Enabled', KeyManager: 'AWS' },
      });
      kmsMock.on(DescribeKeyCommand, { KeyId: 'page1-key' } as any).resolves({
        KeyMetadata: { KeyId: 'page1-key', KeyState: 'Disabled', KeyManager: 'AWS' },
      });
      kmsMock.on(DescribeKeyCommand, { KeyId: 'page2-key' } as any).resolves({
        KeyMetadata: { KeyId: 'page2-key', KeyState: 'Disabled', KeyManager: 'AWS' },
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(kmsMock.commandCalls(ListKeysCommand)).toHaveLength(2);
      const matches = findByCheckId(findings, 'kms_cmk_are_used');
      const keyIds = matches.map((f: any) => f.evidence.keyId).sort();
      expect(keyIds).toEqual(['page1-key', 'page2-key']);
    });

    it('paginates through ListAliases using Marker/Truncated and attaches aliases used by isEnclaveKey detection', async () => {
      kmsMock
        .on(ListAliasesCommand)
        .resolvesOnce({
          Aliases: [{ AliasName: 'alias/not-relevant', TargetKeyId: 'other-key' }],
          Truncated: true,
          NextMarker: 'alias-marker-2',
        })
        .resolvesOnce({
          Aliases: [{ AliasName: 'alias/my-enclave-key', TargetKeyId: 'key-14' }],
          Truncated: false,
        });
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-14' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: {
          KeyId: 'key-14',
          KeyState: 'Enabled',
          KeyManager: 'CUSTOMER',
          MultiRegion: false,
          Description: 'no enclave keyword here',
        },
      });
      kmsMock.on(GetKeyRotationStatusCommand).resolves({ KeyRotationEnabled: true });
      kmsMock.on(GetKeyPolicyCommand).resolves({
        Policy: JSON.stringify({
          Statement: [{
            Sid: 'AllowDecrypt',
            Effect: 'Allow',
            Principal: { AWS: 'arn:aws:iam::123456789012:role/app-role' },
            Action: 'kms:Decrypt',
          }],
        }),
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(kmsMock.commandCalls(ListAliasesCommand)).toHaveLength(2);
      // The alias name (fetched via pagination) contains "enclave", which is enough
      // for isEnclaveKey() to trigger the attestation family of checks.
      expect(findByCheckId(findings, 'kms_key_enclave_attestation_not_enforced')).toHaveLength(1);
    });
  });

  describe('error handling', () => {
    it('does not throw and returns an empty array when ListKeys fails on every retry', async () => {
      jest.useFakeTimers({ advanceTimers: true });
      kmsMock.on(ListKeysCommand).rejects(new Error('AccessDenied'));

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
      jest.useRealTimers();
    });

    it('skips a key that fails DescribeKey but continues scanning remaining keys', async () => {
      jest.useFakeTimers({ advanceTimers: true });
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'broken-key' }, { KeyId: 'fine-key' }] });
      kmsMock.on(DescribeKeyCommand, { KeyId: 'broken-key' } as any).rejects(new Error('AccessDeniedException'));
      kmsMock.on(DescribeKeyCommand, { KeyId: 'fine-key' } as any).resolves({
        KeyMetadata: { KeyId: 'fine-key', KeyState: 'Disabled', KeyManager: 'AWS' },
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      const matches = findByCheckId(findings, 'kms_cmk_are_used');
      expect(matches).toHaveLength(1);
      expect(matches[0].evidence).toMatchObject({ keyId: 'fine-key' });
      jest.useRealTimers();
    });

    it('does not throw and skips rotation finding when GetKeyRotationStatus fails on every retry', async () => {
      jest.useFakeTimers({ advanceTimers: true });
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-15' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: { KeyId: 'key-15', KeyState: 'Enabled', KeyManager: 'CUSTOMER', MultiRegion: false },
      });
      kmsMock.on(GetKeyRotationStatusCommand).rejects(new Error('ThrottlingException'));
      kmsMock.on(GetKeyPolicyCommand).resolves({
        Policy: JSON.stringify({ Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::123456789012:root' } }] }),
      });

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'kms_cmk_rotation_enabled')).toHaveLength(0);
      jest.useRealTimers();
    });

    it('treats an unreadable key policy as null and skips policy-driven findings without throwing', async () => {
      jest.useFakeTimers({ advanceTimers: true });
      kmsMock.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'key-16' }] });
      kmsMock.on(DescribeKeyCommand).resolves({
        KeyMetadata: { KeyId: 'key-16', KeyState: 'Enabled', KeyManager: 'CUSTOMER', MultiRegion: false },
      });
      kmsMock.on(GetKeyRotationStatusCommand).resolves({ KeyRotationEnabled: true });
      kmsMock.on(GetKeyPolicyCommand).rejects(new Error('AccessDenied'));

      const scanner = new KMSScanner(fakeAwsClient);
      const findings = await scanner.scan();

      expect(findByCheckId(findings, 'kms_key_not_publicly_accessible')).toHaveLength(0);
      expect(findByCheckId(findings, 'kms_key_enclave_attestation_not_enforced')).toHaveLength(0);
      jest.useRealTimers();
    });
  });
});
