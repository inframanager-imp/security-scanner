import {
  S3Client,
  ListBucketsCommand,
  GetBucketLocationCommand,
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
  // Buckets can live in any region; a single fixed-region client throws a
  // PermanentRedirect for every call against an out-of-region bucket, and
  // blindly retrying that (as the shared `retry` helper does) turns one
  // misplaced bucket into ~6 checks x 2 retries of pure wasted backoff time.
  // Cache one real client per region instead, resolved once via
  // GetBucketLocation (which itself never redirects).
  private regionalClients = new Map<string, S3Client>();

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

  /** Resolves (and caches) the correctly-regioned S3 client for a bucket, one lookup per bucket. */
  private async getClientForBucket(bucketName: string): Promise<S3Client> {
    try {
      // GetBucketLocation is answerable from any region's endpoint — it's the
      // one call that doesn't itself throw PermanentRedirect.
      const { LocationConstraint } = await this.client.s3.send(
        new GetBucketLocationCommand({ Bucket: bucketName })
      );
      // us-east-1 reports an empty/null constraint; EU buckets report 'EU' for 'eu-west-1'.
      const region = !LocationConstraint ? 'us-east-1'
        : LocationConstraint === 'EU' ? 'eu-west-1'
        : LocationConstraint;

      let regional = this.regionalClients.get(region);
      if (!regional) {
        regional = new S3Client({ ...this.client.getClientConfig(), region });
        this.regionalClients.set(region, regional);
      }
      return regional;
    } catch (error) {
      logger.debug(`Could not resolve region for bucket ${bucketName}, using default client`, {
        error: (error as Error).message,
      });
      return this.client.s3;
    }
  }

  private async validateBucket(bucketName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const s3 = await this.getClientForBucket(bucketName);

    // Check encryption
    const encryptionFindings = await this.checkEncryption(bucketName, s3);
    findings.push(...encryptionFindings);

    // Check versioning
    const versioningFindings = await this.checkVersioning(bucketName, s3);
    findings.push(...versioningFindings);

    // Check public access block
    const publicAccessFindings = await this.checkPublicAccess(bucketName, s3);
    findings.push(...publicAccessFindings);

    // Check ACL
    const aclFindings = await this.checkACL(bucketName, s3);
    findings.push(...aclFindings);

    // Check logging
    const loggingFindings = await this.checkLogging(bucketName, s3);
    findings.push(...loggingFindings);

    const mfaDeleteFindings = await this.checkBucketMFADelete(bucketName, s3);
    findings.push(...mfaDeleteFindings);

    const httpsFindings = await this.checkBucketHTTPS(bucketName, s3);
    findings.push(...httpsFindings);

    return findings;
  }

  private async checkEncryption(bucketName: string, s3: S3Client): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new GetBucketEncryptionCommand({ Bucket: bucketName });
        return await s3.send(cmd);
      });

      if (!result.ServerSideEncryptionConfiguration?.Rules || result.ServerSideEncryptionConfiguration.Rules.length === 0) {
        findings.push(this.emit(
          's3_bucket_default_encryption',
          { bucket: bucketName },
          {
            message: `Bucket "${bucketName}" does not have default encryption enabled`,
            remediation: `Enable SSE-S3 or SSE-KMS encryption for bucket "${bucketName}"`,
          }
        ));
      } else {
        const useKMS = result.ServerSideEncryptionConfiguration.Rules?.some((r: any) => r.ApplyServerSideEncryptionByDefault?.SSEAlgorithm === 'aws:kms');
        if (!useKMS) {
          findings.push(this.emit(
            's3_bucket_kms_encryption',
            { bucket: bucketName, encryption: 'SSE-S3' },
            {
              message: `Bucket "${bucketName}" uses SSE-S3 encryption instead of KMS`,
              remediation: `Consider using KMS encryption (aws:kms) for bucket "${bucketName}" for better key management`,
            }
          ));
        }
      }
    } catch (error) {
      logger.debug(`Failed to check encryption for ${bucketName}`, { error: (error as Error).message });
    }

    return findings;
  }

  private async checkVersioning(bucketName: string, s3: S3Client): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new GetBucketVersioningCommand({ Bucket: bucketName });
        return await s3.send(cmd);
      });

      if (result.Status !== 'Enabled') {
        findings.push(this.emit(
          's3_bucket_object_versioning',
          { bucket: bucketName, status: result.Status },
          {
            message: `Bucket "${bucketName}" does not have versioning enabled`,
            remediation: `Enable versioning for bucket "${bucketName}" to protect against accidental deletions`,
          }
        ));
      }
    } catch (error) {
      logger.debug(`Failed to check versioning for ${bucketName}`, { error: (error as Error).message });
    }

    return findings;
  }

  private async checkPublicAccess(bucketName: string, s3: S3Client): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new GetPublicAccessBlockCommand({ Bucket: bucketName });
        return await s3.send(cmd);
      });

      const config = (result as any).PublicAccessBlockConfiguration;
      if (!config?.BlockPublicAcls || !config?.BlockPublicPolicy || !config?.IgnorePublicAcls || !config?.RestrictPublicBuckets) {
        findings.push(this.emit(
          's3_bucket_level_public_access_block',
          { bucket: bucketName, config },
          {
            message: `Bucket "${bucketName}" does not have all public access block settings enabled`,
            remediation: `Enable all public access block settings for bucket "${bucketName}"`,
          }
        ));
      }
    } catch (error) {
      // Bucket may not exist or may be legacy
      logger.debug(`Failed to check public access for ${bucketName}`, { error: (error as Error).message });
    }

    return findings;
  }

  private async checkACL(bucketName: string, s3: S3Client): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new GetBucketAclCommand({ Bucket: bucketName });
        return await s3.send(cmd);
      });

      // Check for public ACL grants
      const grants = result.Grants || [];
      const publicGrants = grants.filter((g: any) =>
        g.Grantee?.Type === 'Group' &&
        (g.Grantee?.URI?.includes('AllUsers') || g.Grantee?.URI?.includes('AuthenticatedUsers'))
      );

      if (publicGrants.length > 0) {
        findings.push(this.emit(
          's3_bucket_public_access',
          { bucket: bucketName, publicGrants: publicGrants.length },
          {
            message: `Bucket "${bucketName}" has public ACL grants that allow unauthenticated access`,
            remediation: `Remove public ACL grants from bucket "${bucketName}"`,
          }
        ));
      }
    } catch (error) {
      logger.debug(`Failed to check ACL for ${bucketName}`, { error: (error as Error).message });
    }

    return findings;
  }

  private async checkLogging(bucketName: string, s3: S3Client): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new GetBucketLoggingCommand({ Bucket: bucketName });
        return await s3.send(cmd);
      });

      if (!result.LoggingEnabled) {
        findings.push(this.emit(
          's3_bucket_server_access_logging_enabled',
          { bucket: bucketName },
          {
            message: `Bucket "${bucketName}" does not have access logging enabled`,
            remediation: `Enable access logging for bucket "${bucketName}" to track all access requests`,
          }
        ));
      }
    } catch (error) {
      logger.debug(`Failed to check logging for ${bucketName}`, { error: (error as Error).message });
    }

    return findings;
  }

  private async checkBucketMFADelete(bucketName: string, s3: S3Client): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const result = await retry(async () => {
        return await s3.send(new GetBucketVersioningCommand({ Bucket: bucketName }));
      });
      // MFA Delete is only visible when versioning is enabled
      if (result.Status === 'Enabled' && result.MFADelete !== 'Enabled') {
        findings.push(this.emit(
          's3_bucket_no_mfa_delete',
          { bucket: bucketName, mfaDelete: result.MFADelete, versioningStatus: result.Status },
          {
            message: `Bucket "${bucketName}" has versioning enabled but MFA Delete is not enabled. Without MFA Delete, versioned objects can be permanently deleted without MFA.`,
            remediation: `Enable MFA Delete for bucket "${bucketName}" using the AWS CLI with root credentials: aws s3api put-bucket-versioning --bucket ${bucketName} --versioning-configuration MFADelete=Enabled,Status=Enabled --mfa "arn:aws:iam::account:mfa/root-account-mfa-device TOTP_CODE"`,
          }
        ));
      }
    } catch (error) {
      logger.debug(`Failed to check MFA Delete for bucket ${bucketName}`, { error: (error as Error).message });
    }
    return findings;
  }

  private async checkBucketHTTPS(bucketName: string, s3: S3Client): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const result = await retry(async () => {
        return await s3.send(new GetBucketPolicyCommand({ Bucket: bucketName }));
      });
      if (!result.Policy) {
        findings.push(this.emit(
          's3_bucket_secure_transport_policy',
          { bucket: bucketName, hasPolicy: false },
          {
            message: `Bucket "${bucketName}" has no bucket policy. Without a policy denying HTTP access, data may be transmitted unencrypted.`,
            remediation: `Add a bucket policy to "${bucketName}" that denies all HTTP (non-HTTPS) requests using the aws:SecureTransport condition.`,
          }
        ));
      } else {
        const policy = JSON.parse(result.Policy);
        const hasDenyHttp = (policy.Statement ?? []).some((stmt: any) =>
          stmt.Effect === 'Deny' &&
          JSON.stringify(stmt.Condition ?? {}).includes('SecureTransport')
        );
        if (!hasDenyHttp) {
          findings.push(this.emit(
            's3_bucket_secure_transport_policy',
            { bucket: bucketName, hasPolicy: true, hasDenyHttp: false },
            {
              message: `Bucket "${bucketName}" bucket policy does not deny HTTP access (missing aws:SecureTransport=false condition).`,
              remediation: `Update the bucket policy for "${bucketName}" to include a Deny statement with Condition: { "Bool": { "aws:SecureTransport": "false" } }.`,
            }
          ));
        }
      }
    } catch (error) {
      const msg = (error as Error).message;
      if (!msg.includes('NoSuchBucketPolicy') && !msg.includes('AccessDenied')) {
        logger.debug(`Failed to check HTTPS policy for bucket ${bucketName}`, { error: msg });
      } else if (msg.includes('NoSuchBucketPolicy')) {
        // No policy at all — same as not enforcing HTTPS
        findings.push(this.emit(
          's3_bucket_secure_transport_policy',
          { bucket: bucketName, hasPolicy: false },
          {
            message: `Bucket "${bucketName}" has no bucket policy. Without a policy denying HTTP access, data may be transmitted unencrypted.`,
            remediation: `Add a bucket policy to "${bucketName}" that denies all HTTP (non-HTTPS) requests using the aws:SecureTransport condition.`,
          }
        ));
      }
    }
    return findings;
  }
}

export default S3Scanner;
