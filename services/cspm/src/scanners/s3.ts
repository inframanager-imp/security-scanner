import {
  ListBucketsCommand,
  GetBucketEncryptionCommand,
  GetBucketVersioningCommand,
  GetPublicAccessBlockCommand,
  GetBucketAclCommand,
  GetBucketLoggingCommand,
  GetBucketPolicyCommand,
} from '@aws-sdk/client-s3';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class S3Scanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'S3');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting S3 security scan...');

      const buckets = await this.listBuckets();
      for (const bucket of buckets) {
        const bucketName = bucket.Name || 'Unknown';
        logger.debug(`Scanning bucket: ${bucketName}`);

        const bucketFindings = await this.validateBucket(bucketName);
        findings.push(...bucketFindings);
      }

      logger.info(`S3 scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('S3 scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listBuckets(): Promise<any[]> {
    return retry(async () => {
      logger.debug('Fetching S3 buckets...');
      const result = await this.client.s3.send(new ListBucketsCommand({}));
      return result.Buckets || [];
    });
  }

  private async validateBucket(bucketName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    // Check encryption
    const encryptionFindings = await this.checkEncryption(bucketName);
    findings.push(...encryptionFindings);

    // Check versioning
    const versioningFindings = await this.checkVersioning(bucketName);
    findings.push(...versioningFindings);

    // Check public access block
    const publicAccessFindings = await this.checkPublicAccess(bucketName);
    findings.push(...publicAccessFindings);

    // Check ACL
    const aclFindings = await this.checkACL(bucketName);
    findings.push(...aclFindings);

    // Check logging
    const loggingFindings = await this.checkLogging(bucketName);
    findings.push(...loggingFindings);

    const mfaDeleteFindings = await this.checkBucketMFADelete(bucketName);
    findings.push(...mfaDeleteFindings);

    const httpsFindings = await this.checkBucketHTTPS(bucketName);
    findings.push(...httpsFindings);

    return findings;
  }

  private async checkEncryption(bucketName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new GetBucketEncryptionCommand({ Bucket: bucketName });
        return await this.client.s3.send(cmd);
      });

      if (!result.ServerSideEncryptionConfiguration?.Rules || result.ServerSideEncryptionConfiguration.Rules.length === 0) {
        findings.push(this.createFinding(
          'S3 Bucket Not Encrypted',
          `Bucket "${bucketName}" does not have default encryption enabled`,
          'HIGH',
          { bucket: bucketName },
          `Enable SSE-S3 or SSE-KMS encryption for bucket "${bucketName}"`,
          ['s3', 'encryption']
        ));
      } else {
        const useKMS = result.ServerSideEncryptionConfiguration.Rules?.some((r: any) => r.ApplyServerSideEncryptionByDefault?.SSEAlgorithm === 'aws:kms');
        if (!useKMS) {
          findings.push(this.createFinding(
            'Using SSE-S3 Instead of KMS',
            `Bucket "${bucketName}" uses SSE-S3 encryption instead of KMS`,
            'MEDIUM',
            { bucket: bucketName, encryption: 'SSE-S3' },
            `Consider using KMS encryption (aws:kms) for bucket "${bucketName}" for better key management`,
            ['s3', 'encryption', 'kms']
          ));
        }
      }
    } catch (error) {
      logger.debug(`Failed to check encryption for ${bucketName}`, { error: (error as Error).message });
    }

    return findings;
  }

  private async checkVersioning(bucketName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new GetBucketVersioningCommand({ Bucket: bucketName });
        return await this.client.s3.send(cmd);
      });

      if (result.Status !== 'Enabled') {
        findings.push(this.createFinding(
          'S3 Versioning Not Enabled',
          `Bucket "${bucketName}" does not have versioning enabled`,
          'MEDIUM',
          { bucket: bucketName, status: result.Status },
          `Enable versioning for bucket "${bucketName}" to protect against accidental deletions`,
          ['s3', 'versioning', 'data-protection']
        ));
      }
    } catch (error) {
      logger.debug(`Failed to check versioning for ${bucketName}`, { error: (error as Error).message });
    }

    return findings;
  }

  private async checkPublicAccess(bucketName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new GetPublicAccessBlockCommand({ Bucket: bucketName });
        return await this.client.s3.send(cmd);
      });

      const config = (result as any).PublicAccessBlockConfiguration;
      if (!config?.BlockPublicAcls || !config?.BlockPublicPolicy || !config?.IgnorePublicAcls || !config?.RestrictPublicBuckets) {
        findings.push(this.createFinding(
          'Public Access Not Fully Blocked',
          `Bucket "${bucketName}" does not have all public access block settings enabled`,
          'CRITICAL',
          { bucket: bucketName, config },
          `Enable all public access block settings for bucket "${bucketName}"`,
          ['s3', 'public-access', 'security']
        ));
      }
    } catch (error) {
      // Bucket may not exist or may be legacy
      logger.debug(`Failed to check public access for ${bucketName}`, { error: (error as Error).message });
    }

    return findings;
  }

  private async checkACL(bucketName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new GetBucketAclCommand({ Bucket: bucketName });
        return await this.client.s3.send(cmd);
      });

      // Check for public ACL grants
      const grants = result.Grants || [];
      const publicGrants = grants.filter((g: any) =>
        g.Grantee?.Type === 'Group' &&
        (g.Grantee?.URI?.includes('AllUsers') || g.Grantee?.URI?.includes('AuthenticatedUsers'))
      );

      if (publicGrants.length > 0) {
        findings.push(this.createFinding(
          'Bucket Has Public ACL Grants',
          `Bucket "${bucketName}" has public ACL grants that allow unauthenticated access`,
          'CRITICAL',
          { bucket: bucketName, publicGrants: publicGrants.length },
          `Remove public ACL grants from bucket "${bucketName}"`,
          ['s3', 'acl', 'public-access']
        ));
      }
    } catch (error) {
      logger.debug(`Failed to check ACL for ${bucketName}`, { error: (error as Error).message });
    }

    return findings;
  }

  private async checkLogging(bucketName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new GetBucketLoggingCommand({ Bucket: bucketName });
        return await this.client.s3.send(cmd);
      });

      if (!result.LoggingEnabled) {
        findings.push(this.createFinding(
          'S3 Access Logging Not Enabled',
          `Bucket "${bucketName}" does not have access logging enabled`,
          'MEDIUM',
          { bucket: bucketName },
          `Enable access logging for bucket "${bucketName}" to track all access requests`,
          ['s3', 'logging', 'audit']
        ));
      }
    } catch (error) {
      logger.debug(`Failed to check logging for ${bucketName}`, { error: (error as Error).message });
    }

    return findings;
  }

  private async checkBucketMFADelete(bucketName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const result = await retry(async () => {
        return await this.client.s3.send(new GetBucketVersioningCommand({ Bucket: bucketName }));
      });
      // MFA Delete is only visible when versioning is enabled
      if (result.Status === 'Enabled' && result.MFADelete !== 'Enabled') {
        findings.push(this.createFinding(
          'S3 MFA Delete Not Enabled',
          `Bucket "${bucketName}" has versioning enabled but MFA Delete is not enabled. Without MFA Delete, versioned objects can be permanently deleted without MFA.`,
          'MEDIUM',
          { bucket: bucketName, mfaDelete: result.MFADelete, versioningStatus: result.Status },
          `Enable MFA Delete for bucket "${bucketName}" using the AWS CLI with root credentials: aws s3api put-bucket-versioning --bucket ${bucketName} --versioning-configuration MFADelete=Enabled,Status=Enabled --mfa "arn:aws:iam::account:mfa/root-account-mfa-device TOTP_CODE"`,
          ['s3', 'mfa-delete', 'versioning', 'cis-2.1.2']
        ));
      }
    } catch (error) {
      logger.debug(`Failed to check MFA Delete for bucket ${bucketName}`, { error: (error as Error).message });
    }
    return findings;
  }

  private async checkBucketHTTPS(bucketName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const result = await retry(async () => {
        return await this.client.s3.send(new GetBucketPolicyCommand({ Bucket: bucketName }));
      });
      if (!result.Policy) {
        findings.push(this.createFinding(
          'S3 HTTPS Not Enforced',
          `Bucket "${bucketName}" has no bucket policy. Without a policy denying HTTP access, data may be transmitted unencrypted.`,
          'MEDIUM',
          { bucket: bucketName, hasPolicy: false },
          `Add a bucket policy to "${bucketName}" that denies all HTTP (non-HTTPS) requests using the aws:SecureTransport condition.`,
          ['s3', 'https', 'encryption-in-transit', 'cis-2.1.1']
        ));
      } else {
        const policy = JSON.parse(result.Policy);
        const hasDenyHttp = (policy.Statement ?? []).some((stmt: any) =>
          stmt.Effect === 'Deny' &&
          JSON.stringify(stmt.Condition ?? {}).includes('SecureTransport')
        );
        if (!hasDenyHttp) {
          findings.push(this.createFinding(
            'S3 HTTPS Not Enforced',
            `Bucket "${bucketName}" bucket policy does not deny HTTP access (missing aws:SecureTransport=false condition).`,
            'MEDIUM',
            { bucket: bucketName, hasPolicy: true, hasDenyHttp: false },
            `Update the bucket policy for "${bucketName}" to include a Deny statement with Condition: { "Bool": { "aws:SecureTransport": "false" } }.`,
            ['s3', 'https', 'encryption-in-transit', 'cis-2.1.1']
          ));
        }
      }
    } catch (error) {
      const msg = (error as Error).message;
      if (!msg.includes('NoSuchBucketPolicy') && !msg.includes('AccessDenied')) {
        logger.debug(`Failed to check HTTPS policy for bucket ${bucketName}`, { error: msg });
      } else if (msg.includes('NoSuchBucketPolicy')) {
        // No policy at all — same as not enforcing HTTPS
        findings.push(this.createFinding(
          'S3 HTTPS Not Enforced',
          `Bucket "${bucketName}" has no bucket policy. Without a policy denying HTTP access, data may be transmitted unencrypted.`,
          'MEDIUM',
          { bucket: bucketName, hasPolicy: false },
          `Add a bucket policy to "${bucketName}" that denies all HTTP (non-HTTPS) requests using the aws:SecureTransport condition.`,
          ['s3', 'https', 'encryption-in-transit', 'cis-2.1.1']
        ));
      }
    }
    return findings;
  }
}

export default S3Scanner;
