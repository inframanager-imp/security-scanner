import { describe, it, expect } from '@jest/globals';
import { resourceFingerprint, dedupKey } from '../../src/services/dedupService';

describe('dedupService', () => {
  describe('resourceFingerprint', () => {
    it('prefers resourceId over every other key when present', () => {
      expect(
        resourceFingerprint({ resourceId: 'r-1', bucket: 'my-bucket', arn: 'arn:aws:...' }),
      ).toBe('r-1');
    });

    it('falls back through the service-specific key list in priority order', () => {
      expect(resourceFingerprint({ functionName: 'fn-1' })).toBe('fn-1');
      expect(resourceFingerprint({ trailName: 'trail-1' })).toBe('trail-1');
      expect(resourceFingerprint({ bucket: 'bucket-1' })).toBe('bucket-1');
      expect(resourceFingerprint({ username: 'user-1' })).toBe('user-1');
      expect(resourceFingerprint({ accessKeyId: 'AKIA...' })).toBe('AKIA...');
      expect(resourceFingerprint({ sgId: 'sg-1' })).toBe('sg-1');
      expect(resourceFingerprint({ vpcId: 'vpc-1' })).toBe('vpc-1');
      expect(resourceFingerprint({ arn: 'arn:aws:iam::1:role/x' })).toBe('arn:aws:iam::1:role/x');
    });

    it('picks the first matching key when multiple are present, per declared order', () => {
      // bucket is declared before arn in the key list.
      expect(resourceFingerprint({ arn: 'arn:aws:...', bucket: 'my-bucket' })).toBe('my-bucket');
    });

    it('falls back to account-level when evidence has none of the known keys', () => {
      expect(resourceFingerprint({ someOtherField: 'x' })).toBe('account-level');
    });

    it('falls back to account-level for null, undefined, or non-object evidence', () => {
      expect(resourceFingerprint(null)).toBe('account-level');
      expect(resourceFingerprint(undefined)).toBe('account-level');
      expect(resourceFingerprint('not-an-object')).toBe('account-level');
    });

    it('coerces non-string key values to strings', () => {
      expect(resourceFingerprint({ resourceId: 12345 })).toBe('12345');
    });

    it('treats an empty string value as present (not skipped)', () => {
      // `!= null` only excludes null/undefined — '' and 0 are valid fingerprints.
      expect(resourceFingerprint({ resourceId: '' })).toBe('');
    });
  });

  describe('dedupKey', () => {
    it('uses checkId:fingerprint when checkId is provided', () => {
      expect(dedupKey('S3', 'Bucket encryption disabled', 's3_bucket_default_encryption', { bucket: 'b1' }))
        .toBe('s3_bucket_default_encryption:b1');
    });

    it('falls back to service:title:fingerprint when checkId is null', () => {
      expect(dedupKey('S3', 'Bucket encryption disabled', null, { bucket: 'b1' }))
        .toBe('S3:Bucket encryption disabled:b1');
    });

    it('stays stable across a title reword when checkId is unchanged', () => {
      const before = dedupKey('IAM', 'Old title', 'iam_user_hardware_mfa_enabled', { username: 'alice' });
      const after = dedupKey('IAM', 'New reworded title', 'iam_user_hardware_mfa_enabled', { username: 'alice' });
      expect(before).toBe(after);
    });

    it('changes when the title changes and checkId is null (legacy behavior)', () => {
      const before = dedupKey('IAM', 'Old title', null, { username: 'alice' });
      const after = dedupKey('IAM', 'New reworded title', null, { username: 'alice' });
      expect(before).not.toBe(after);
    });

    it('produces distinct keys for distinct resources under the same check', () => {
      const keyA = dedupKey('S3', 'Bucket encryption disabled', 's3_bucket_default_encryption', { bucket: 'bucket-a' });
      const keyB = dedupKey('S3', 'Bucket encryption disabled', 's3_bucket_default_encryption', { bucket: 'bucket-b' });
      expect(keyA).not.toBe(keyB);
    });
  });
});
