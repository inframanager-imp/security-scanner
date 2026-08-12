// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  ListBucketsCommand,
  GetBucketEncryptionCommand,
  GetBucketVersioningCommand,
  GetPublicAccessBlockCommand,
  GetBucketAclCommand,
  GetBucketLoggingCommand,
  GetBucketPolicyCommand,
  GetBucketLocationCommand,
  GetBucketOwnershipControlsCommand,
  GetObjectLockConfigurationCommand,
  GetBucketLifecycleConfigurationCommand,
  GetBucketReplicationCommand,
  GetBucketNotificationConfigurationCommand,
  ListObjectsV2Command,
  GetObjectAclCommand,
  HeadBucketCommand,
} from '@aws-sdk/client-s3';
import {
  S3ControlClient,
  GetPublicAccessBlockCommand as GetAccountPublicAccessBlockCommand,
  ListAccessPointsCommand,
  GetAccessPointCommand,
  ListMultiRegionAccessPointsCommand,
} from '@aws-sdk/client-s3-control';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

/** ACL grantee groups that make a bucket/object effectively public. */
const PUBLIC_ACL_URIS = [
  'http://acs.amazonaws.com/groups/global/AllUsers',
  'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
];

/** Condition keys that scope a wildcard principal to a specific account/org/network. */
const RESTRICTIVE_CONDITION_KEYS = [
  'aws:sourceaccount',
  'aws:sourcearn',
  'aws:sourceowner',
  'aws:sourcevpc',
  'aws:sourcevpce',
  'aws:principalaccount',
  'aws:principalarn',
  'aws:principalorgid',
  'aws:principalorgpaths',
];

/** Concrete write actions a public principal must not be granted (plus s3:*, s3:Put*, s3:Delete*). */
const PUBLIC_WRITE_ACTIONS = ['s3:putobject', 's3:deleteobject'];

/** Cap for the s3_bucket_object_public spot-check (mirrors Prowler's defaults). */
const OBJECT_PUBLIC_MAX_OBJECTS = 100;
const OBJECT_PUBLIC_SAMPLE_SIZE = 3;

/** Table-driven family: public-list vs public-write bucket ACL checks. */
const PUBLIC_ACL_PERMISSION_CHECKS: { checkId: string; permissions: string[]; verb: string }[] = [
  { checkId: 's3_bucket_public_list_acl', permissions: ['FULL_CONTROL', 'READ', 'READ_ACP'], verb: 'listable' },
  { checkId: 's3_bucket_public_write_acl', permissions: ['FULL_CONTROL', 'WRITE', 'WRITE_ACP'], verb: 'writable' },
];

/** Predictable service bucket names from the "Bucket Monopoly" shadow-resource research. */
const SHADOW_BUCKET_PATTERNS: { service: string; pattern: string }[] = [
  { service: 'Glue', pattern: 'aws-glue-assets-<account>-<region>' },
  { service: 'SageMaker', pattern: 'sagemaker-<region>-<account>' },
  { service: 'EMR', pattern: 'aws-emr-studio-<account>-<region>' },
  { service: 'CodeStar', pattern: 'aws-codestar-<region>-<account>' },
];

interface PublicAccessBlockState {
  blockPublicAcls: boolean;
  ignorePublicAcls: boolean;
  blockPublicPolicy: boolean;
  restrictPublicBuckets: boolean;
}

interface BucketState {
  name: string;
  region: string;
  /** Raw GetBucketVersioning result; null when the call failed */
  versioning: any;
  /** Raw PublicAccessBlockConfiguration; undefined when the call failed or no config exists */
  pabRaw: any;
  /** Normalized PAB (missing config -> all false); null when the call failed */
  publicAccessBlock: PublicAccessBlockState | null;
  /** ACL grants; null when the call failed */
  aclGrants: any[] | null;
  /** Canonical owner id from the bucket ACL */
  ownerId: string;
  /** Parsed bucket policy ({} = no policy); null when the call failed */
  policy: any;
  /** ObjectOwnership setting; null = no ownership controls; undefined = call failed */
  ownership: string | null | undefined;
  /** undefined = call failed */
  objectLock: boolean | undefined;
  /** undefined = call failed; [] = no lifecycle configuration */
  lifecycleRules: any[] | undefined;
  /** undefined = call failed; [] = no replication configuration */
  replicationRules: any[] | undefined;
  /** undefined = call failed */
  hasNotificationConfig: boolean | undefined;
}

export class S3Scanner extends BaseScanner {
  private s3control: S3ControlClient;

  constructor(client: AWSClient) {
    super(client, 'S3');
    this.s3control = new S3ControlClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting S3 security scan...');

      let accountId: string | null = null;
      try {
        accountId = await this.client.getAccountId();
      } catch (error) {
        logger.debug('Failed to resolve AWS account id for S3 scan', { error: (error as Error).message });
      }

      const { buckets, canonicalId } = await this.listBuckets();
      const accountPab = await this.getAccountPublicAccessBlock(accountId);

      const bucketStates: BucketState[] = [];
      for (const bucket of buckets) {
        const bucketName = bucket.Name || 'Unknown';
        logger.debug(`Scanning bucket: ${bucketName}`);

        try {
          const state = await this.fetchBucketState(bucketName);
          bucketStates.push(state);
          findings.push(...(await this.validateBucket(state, accountPab, accountId)));
        } catch (error) {
          logger.debug(`Failed to scan bucket ${bucketName}`, { error: (error as Error).message });
        }
      }

      findings.push(...this.checkAccountLevelPublicAccessBlocks(accountPab, accountId, buckets.length));
      findings.push(...this.checkCrossRegionReplication(bucketStates));
      findings.push(...(await this.checkShadowResources(bucketStates, accountId, canonicalId)));
      findings.push(...(await this.scanAccessPoints(accountId)));
      findings.push(...(await this.scanMultiRegionAccessPoints(accountId)));

      logger.info(`S3 scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('S3 scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listBuckets(): Promise<{ buckets: any[]; canonicalId: string }> {
    return retry(async () => {
      logger.debug('Fetching S3 buckets...');
      const result = await this.client.s3.send(new ListBucketsCommand({}));
      return { buckets: result.Buckets || [], canonicalId: result.Owner?.ID ?? '' };
    });
  }

  private isErrorCode(error: any, code: string): boolean {
    return error?.name === code || error?.Code === code || String(error?.message ?? '').includes(code);
  }

  /** Fetch all per-bucket state shared by the checks (one API call per attribute). */
  private async fetchBucketState(bucketName: string): Promise<BucketState> {
    const state: BucketState = {
      name: bucketName,
      region: this.client.getRegion(),
      versioning: null,
      pabRaw: undefined,
      publicAccessBlock: null,
      aclGrants: null,
      ownerId: '',
      policy: null,
      ownership: undefined,
      objectLock: undefined,
      lifecycleRules: undefined,
      replicationRules: undefined,
      hasNotificationConfig: undefined,
    };

    try {
      const location: any = await retry(async () => {
        return await this.client.s3.send(new GetBucketLocationCommand({ Bucket: bucketName }));
      });
      const constraint = location.LocationConstraint;
      // Prowler: "EU" means eu-west-1, empty means us-east-1
      state.region = constraint === 'EU' ? 'eu-west-1' : (constraint || 'us-east-1');
    } catch (error) {
      logger.debug(`Failed to get location for bucket ${bucketName}`, { error: (error as Error).message });
    }

    try {
      state.versioning = await retry(async () => {
        return await this.client.s3.send(new GetBucketVersioningCommand({ Bucket: bucketName }));
      });
    } catch (error) {
      logger.debug(`Failed to check versioning for ${bucketName}`, { error: (error as Error).message });
    }

    try {
      const result: any = await retry(async () => {
        try {
          return await this.client.s3.send(new GetPublicAccessBlockCommand({ Bucket: bucketName }));
        } catch (error) {
          if (this.isErrorCode(error, 'NoSuchPublicAccessBlockConfiguration')) return null;
          throw error;
        }
      });
      if (result === null) {
        // No configuration at all behaves as if every setting were disabled
        state.publicAccessBlock = {
          blockPublicAcls: false,
          ignorePublicAcls: false,
          blockPublicPolicy: false,
          restrictPublicBuckets: false,
        };
      } else {
        const config: any = result.PublicAccessBlockConfiguration ?? {};
        state.pabRaw = config;
        state.publicAccessBlock = {
          blockPublicAcls: !!config.BlockPublicAcls,
          ignorePublicAcls: !!config.IgnorePublicAcls,
          blockPublicPolicy: !!config.BlockPublicPolicy,
          restrictPublicBuckets: !!config.RestrictPublicBuckets,
        };
      }
    } catch (error) {
      logger.debug(`Failed to check public access for ${bucketName}`, { error: (error as Error).message });
    }

    try {
      const acl: any = await retry(async () => {
        return await this.client.s3.send(new GetBucketAclCommand({ Bucket: bucketName }));
      });
      state.aclGrants = acl.Grants ?? [];
      state.ownerId = acl.Owner?.ID ?? '';
    } catch (error) {
      logger.debug(`Failed to check ACL for ${bucketName}`, { error: (error as Error).message });
    }

    try {
      const result: any = await retry(async () => {
        try {
          return await this.client.s3.send(new GetBucketPolicyCommand({ Bucket: bucketName }));
        } catch (error) {
          if (this.isErrorCode(error, 'NoSuchBucketPolicy')) return null;
          throw error;
        }
      });
      state.policy = result?.Policy ? JSON.parse(result.Policy) : {};
    } catch (error) {
      logger.debug(`Failed to get bucket policy for ${bucketName}`, { error: (error as Error).message });
    }

    try {
      const result: any = await retry(async () => {
        try {
          return await this.client.s3.send(new GetBucketOwnershipControlsCommand({ Bucket: bucketName }));
        } catch (error) {
          if (this.isErrorCode(error, 'OwnershipControlsNotFoundError')) return null;
          throw error;
        }
      });
      state.ownership = result === null ? null : (result.OwnershipControls?.Rules?.[0]?.ObjectOwnership ?? null);
    } catch (error) {
      logger.debug(`Failed to get ownership controls for ${bucketName}`, { error: (error as Error).message });
    }

    try {
      state.objectLock = await retry(async () => {
        try {
          await this.client.s3.send(new GetObjectLockConfigurationCommand({ Bucket: bucketName }));
          return true;
        } catch (error) {
          if (this.isErrorCode(error, 'ObjectLockConfigurationNotFoundError')) return false;
          throw error;
        }
      });
    } catch (error) {
      logger.debug(`Failed to get object lock configuration for ${bucketName}`, { error: (error as Error).message });
    }

    try {
      const result: any = await retry(async () => {
        try {
          return await this.client.s3.send(new GetBucketLifecycleConfigurationCommand({ Bucket: bucketName }));
        } catch (error) {
          if (this.isErrorCode(error, 'NoSuchLifecycleConfiguration')) return { Rules: [] };
          throw error;
        }
      });
      state.lifecycleRules = result.Rules ?? [];
    } catch (error) {
      logger.debug(`Failed to get lifecycle configuration for ${bucketName}`, { error: (error as Error).message });
    }

    try {
      const result: any = await retry(async () => {
        try {
          return await this.client.s3.send(new GetBucketReplicationCommand({ Bucket: bucketName }));
        } catch (error) {
          if (this.isErrorCode(error, 'ReplicationConfigurationNotFoundError')) return null;
          throw error;
        }
      });
      state.replicationRules = result === null ? [] : (result.ReplicationConfiguration?.Rules ?? []);
    } catch (error) {
      logger.debug(`Failed to get replication configuration for ${bucketName}`, { error: (error as Error).message });
    }

    try {
      const config: any = await retry(async () => {
        return await this.client.s3.send(new GetBucketNotificationConfigurationCommand({ Bucket: bucketName }));
      });
      state.hasNotificationConfig = !!(
        (config.TopicConfigurations && config.TopicConfigurations.length > 0) ||
        (config.QueueConfigurations && config.QueueConfigurations.length > 0) ||
        (config.LambdaFunctionConfigurations && config.LambdaFunctionConfigurations.length > 0) ||
        config.EventBridgeConfiguration
      );
    } catch (error) {
      logger.debug(`Failed to get notification configuration for ${bucketName}`, { error: (error as Error).message });
    }

    return state;
  }

  private async validateBucket(
    state: BucketState,
    accountPab: PublicAccessBlockState | null,
    accountId: string | null
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    findings.push(...(await this.checkEncryption(state.name)));
    findings.push(...this.checkVersioning(state));
    findings.push(...this.checkPublicAccess(state));
    findings.push(...this.checkACL(state));
    findings.push(...(await this.checkLogging(state.name)));
    findings.push(...this.checkBucketMFADelete(state));
    findings.push(...this.checkBucketHTTPS(state));

    findings.push(...this.checkAclProhibited(state));
    findings.push(...this.checkObjectLock(state));
    findings.push(...this.checkLifecycle(state));
    findings.push(...this.checkEventNotifications(state));
    findings.push(...this.checkCrossAccountAccess(state, accountId));
    findings.push(...this.checkPolicyPublicWriteAccess(state, accountPab));

    // Prowler skips the per-bucket ACL checks entirely when the account-level
    // block already neutralizes public ACLs and public bucket policies.
    const accountBlocksPublicAcls = !!(accountPab && accountPab.ignorePublicAcls && accountPab.restrictPublicBuckets);
    if (!accountBlocksPublicAcls) {
      findings.push(...this.checkPublicAclPermissions(state));
    }

    findings.push(...(await this.checkObjectPublic(state)));

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

  private checkVersioning(state: BucketState): ScanningResult[] {
    const findings: ScanningResult[] = [];

    if (state.versioning && state.versioning.Status !== 'Enabled') {
      findings.push(this.emit(
        's3_bucket_object_versioning',
        { bucket: state.name, status: state.versioning.Status },
        {
          message: `Bucket "${state.name}" does not have versioning enabled`,
          remediation: `Enable versioning for bucket "${state.name}" to protect against accidental deletions`,
        }
      ));
    }

    return findings;
  }

  private checkPublicAccess(state: BucketState): ScanningResult[] {
    const findings: ScanningResult[] = [];

    if (state.pabRaw !== undefined) {
      const config = state.pabRaw;
      if (!config?.BlockPublicAcls || !config?.BlockPublicPolicy || !config?.IgnorePublicAcls || !config?.RestrictPublicBuckets) {
        findings.push(this.emit(
          's3_bucket_level_public_access_block',
          { bucket: state.name, config },
          {
            message: `Bucket "${state.name}" does not have all public access block settings enabled`,
            remediation: `Enable all public access block settings for bucket "${state.name}"`,
          }
        ));
      }
    }

    return findings;
  }

  private checkACL(state: BucketState): ScanningResult[] {
    const findings: ScanningResult[] = [];

    if (state.aclGrants) {
      const publicGrants = state.aclGrants.filter((g: any) =>
        g.Grantee?.Type === 'Group' &&
        (g.Grantee?.URI?.includes('AllUsers') || g.Grantee?.URI?.includes('AuthenticatedUsers'))
      );

      if (publicGrants.length > 0) {
        findings.push(this.emit(
          's3_bucket_public_access',
          { bucket: state.name, publicGrants: publicGrants.length },
          {
            message: `Bucket "${state.name}" has public ACL grants that allow unauthenticated access`,
            remediation: `Remove public ACL grants from bucket "${state.name}"`,
          }
        ));
      }
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

  private checkBucketMFADelete(state: BucketState): ScanningResult[] {
    const findings: ScanningResult[] = [];

    // MFA Delete is only visible when versioning is enabled
    if (state.versioning && state.versioning.Status === 'Enabled' && state.versioning.MFADelete !== 'Enabled') {
      findings.push(this.emit(
        's3_bucket_no_mfa_delete',
        { bucket: state.name, mfaDelete: state.versioning.MFADelete, versioningStatus: state.versioning.Status },
        {
          message: `Bucket "${state.name}" has versioning enabled but MFA Delete is not enabled. Without MFA Delete, versioned objects can be permanently deleted without MFA.`,
          remediation: `Enable MFA Delete for bucket "${state.name}" using the AWS CLI with root credentials: aws s3api put-bucket-versioning --bucket ${state.name} --versioning-configuration MFADelete=Enabled,Status=Enabled --mfa "arn:aws:iam::account:mfa/root-account-mfa-device TOTP_CODE"`,
        }
      ));
    }

    return findings;
  }

  private checkBucketHTTPS(state: BucketState): ScanningResult[] {
    const findings: ScanningResult[] = [];

    if (state.policy === null) return findings;

    if (!this.hasPolicyStatements(state.policy)) {
      findings.push(this.emit(
        's3_bucket_secure_transport_policy',
        { bucket: state.name, hasPolicy: false },
        {
          message: `Bucket "${state.name}" has no bucket policy. Without a policy denying HTTP access, data may be transmitted unencrypted.`,
          remediation: `Add a bucket policy to "${state.name}" that denies all HTTP (non-HTTPS) requests using the aws:SecureTransport condition.`,
        }
      ));
    } else {
      const hasDenyHttp = this.toArray(state.policy.Statement).some((stmt: any) =>
        stmt.Effect === 'Deny' &&
        JSON.stringify(stmt.Condition ?? {}).includes('SecureTransport')
      );
      if (!hasDenyHttp) {
        findings.push(this.emit(
          's3_bucket_secure_transport_policy',
          { bucket: state.name, hasPolicy: true, hasDenyHttp: false },
          {
            message: `Bucket "${state.name}" bucket policy does not deny HTTP access (missing aws:SecureTransport=false condition).`,
            remediation: `Update the bucket policy for "${state.name}" to include a Deny statement with Condition: { "Bool": { "aws:SecureTransport": "false" } }.`,
          }
        ));
      }
    }

    return findings;
  }

  // ---------------------------------------------------------------------------
  // Ported Prowler checks (per bucket)
  // ---------------------------------------------------------------------------

  private checkAclProhibited(state: BucketState): ScanningResult[] {
    const findings: ScanningResult[] = [];

    if (state.ownership === undefined) return findings; // could not read ownership controls

    if (!state.ownership || !state.ownership.includes('BucketOwnerEnforced')) {
      findings.push(this.emit(
        's3_bucket_acl_prohibited',
        { bucket: state.name, objectOwnership: state.ownership ?? null },
        {
          message: `Bucket "${state.name}" has bucket ACLs enabled (Object Ownership is ${state.ownership ?? 'not configured'})`,
          remediation: `Disable ACLs on bucket "${state.name}": aws s3api put-bucket-ownership-controls --bucket ${state.name} --ownership-controls "Rules=[{ObjectOwnership=BucketOwnerEnforced}]"`,
        }
      ));
    }

    return findings;
  }

  private checkObjectLock(state: BucketState): ScanningResult[] {
    const findings: ScanningResult[] = [];

    if (state.objectLock === false) {
      findings.push(this.emit(
        's3_bucket_object_lock',
        { bucket: state.name, objectLock: false },
        {
          message: `Bucket "${state.name}" has Object Lock disabled`,
          remediation: `Enable Object Lock (WORM) on bucket "${state.name}": aws s3api put-object-lock-configuration --bucket ${state.name} --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"GOVERNANCE","Days":1}}}' (requires versioning)`,
        }
      ));
    }

    return findings;
  }

  private checkLifecycle(state: BucketState): ScanningResult[] {
    const findings: ScanningResult[] = [];

    if (state.lifecycleRules === undefined) return findings;

    const hasEnabledRule = state.lifecycleRules.some((rule: any) => rule.Status === 'Enabled');
    if (!hasEnabledRule) {
      findings.push(this.emit(
        's3_bucket_lifecycle_enabled',
        { bucket: state.name, lifecycleRules: state.lifecycleRules.length },
        {
          message: `Bucket "${state.name}" does not have an enabled lifecycle configuration`,
          remediation: `Add an enabled lifecycle rule to bucket "${state.name}" (e.g. abort incomplete multipart uploads after 7 days and expire or transition aged objects)`,
        }
      ));
    }

    return findings;
  }

  private checkEventNotifications(state: BucketState): ScanningResult[] {
    const findings: ScanningResult[] = [];

    if (state.hasNotificationConfig === false) {
      findings.push(this.emit(
        's3_bucket_event_notifications_enabled',
        { bucket: state.name, notificationConfig: false },
        {
          message: `Bucket "${state.name}" does not have event notifications enabled`,
          remediation: `Enable event notifications on bucket "${state.name}", e.g. aws s3api put-bucket-notification-configuration --bucket ${state.name} --notification-configuration '{"EventBridgeConfiguration": {}}'`,
        }
      ));
    }

    return findings;
  }

  private checkCrossAccountAccess(state: BucketState, accountId: string | null): ScanningResult[] {
    const findings: ScanningResult[] = [];

    if (!accountId || state.policy === null || !this.hasPolicyStatements(state.policy)) return findings;

    const crossAccount = this.policyAllowsCrossAccountAccess(state.policy, accountId);
    if (crossAccount) {
      findings.push(this.emit(
        's3_bucket_cross_account_access',
        { bucket: state.name, principal: crossAccount.principal },
        {
          message: `Bucket "${state.name}" has a bucket policy allowing cross-account access (principal "${crossAccount.principal}")`,
          remediation: `Restrict the bucket policy of "${state.name}" to principals in the bucket owner's account, or scope external access with conditions such as aws:PrincipalOrgID`,
        }
      ));
    }

    return findings;
  }

  private checkPolicyPublicWriteAccess(state: BucketState, accountPab: PublicAccessBlockState | null): ScanningResult[] {
    const findings: ScanningResult[] = [];

    if (state.policy === null || !this.hasPolicyStatements(state.policy)) return findings;
    // Public bucket policies are neutralized when RestrictPublicBuckets is on at either level
    if (accountPab && accountPab.restrictPublicBuckets) return findings;
    if (state.publicAccessBlock && state.publicAccessBlock.restrictPublicBuckets) return findings;

    const publicWrite = this.policyAllowsPublicWrite(state.policy);
    if (publicWrite) {
      findings.push(this.emit(
        's3_bucket_policy_public_write_access',
        { bucket: state.name, action: publicWrite.action },
        {
          message: `Bucket "${state.name}" bucket policy allows public write access (action "${publicWrite.action}" granted to all principals)`,
          remediation: `Remove public write statements from the bucket policy of "${state.name}" and enable RestrictPublicBuckets: aws s3api put-public-access-block --bucket ${state.name} --public-access-block-configuration RestrictPublicBuckets=true`,
        }
      ));
    }

    return findings;
  }

  /** Table-driven pair: s3_bucket_public_list_acl / s3_bucket_public_write_acl. */
  private checkPublicAclPermissions(state: BucketState): ScanningResult[] {
    const findings: ScanningResult[] = [];

    // Prowler only evaluates buckets whose public access block state is known
    if (!state.publicAccessBlock || !state.aclGrants) return findings;
    if (state.publicAccessBlock.ignorePublicAcls && state.publicAccessBlock.restrictPublicBuckets) return findings;

    for (const { checkId, permissions, verb } of PUBLIC_ACL_PERMISSION_CHECKS) {
      const grant = state.aclGrants.find((g: any) => {
        const uri: string = g.Grantee?.URI ?? '';
        return (
          g.Grantee?.Type === 'Group' &&
          (uri.includes('AllUsers') || uri.includes('AuthenticatedUsers')) &&
          permissions.includes(g.Permission)
        );
      });

      if (grant) {
        const group = String(grant.Grantee?.URI ?? '').split('/').pop() ?? 'AllUsers';
        findings.push(this.emit(
          checkId,
          { bucket: state.name, grantee: grant.Grantee?.URI, permission: grant.Permission },
          {
            message: `Bucket "${state.name}" is publicly ${verb} due to its bucket ACL: ${group} has the ${grant.Permission} permission`,
            remediation: `Remove the ${grant.Permission} ACL grant for ${group} on bucket "${state.name}" and enable IgnorePublicAcls and RestrictPublicBuckets in its Block Public Access settings`,
          }
        ));
      }
    }

    return findings;
  }

  /** Spot-check a capped, deterministic sample of object ACLs for public grants. */
  private async checkObjectPublic(state: BucketState): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const listed: any = await retry(async () => {
        return await this.client.s3.send(new ListObjectsV2Command({ Bucket: state.name, MaxKeys: OBJECT_PUBLIC_MAX_OBJECTS }));
      });
      const keys: string[] = (listed.Contents ?? []).map((obj: any) => obj.Key).filter((key: any) => !!key);
      if (keys.length === 0) return findings; // empty bucket -> nothing to sample

      // Deterministic, evenly-spaced sampling so findings are reproducible across scans
      let sampleKeys: string[];
      if (keys.length <= OBJECT_PUBLIC_SAMPLE_SIZE) {
        sampleKeys = keys;
      } else {
        const step = Math.floor(keys.length / OBJECT_PUBLIC_SAMPLE_SIZE);
        sampleKeys = [];
        for (let i = 0; i < OBJECT_PUBLIC_SAMPLE_SIZE; i++) {
          sampleKeys.push(keys[i * step]);
        }
      }

      const publicKeys: string[] = [];
      for (const key of sampleKeys) {
        try {
          const acl: any = await retry(async () => {
            return await this.client.s3.send(new GetObjectAclCommand({ Bucket: state.name, Key: key }));
          });
          const isPublic = (acl.Grants ?? []).some((g: any) =>
            g.Grantee?.Type === 'Group' && PUBLIC_ACL_URIS.includes(g.Grantee?.URI ?? '')
          );
          if (isPublic) publicKeys.push(key);
        } catch (error) {
          logger.debug(`Failed to get object ACL for ${state.name}/${key}`, { error: (error as Error).message });
        }
      }

      if (publicKeys.length > 0) {
        findings.push(this.emit(
          's3_bucket_object_public',
          { bucket: state.name, sampledObjects: sampleKeys.length, publicObjects: publicKeys },
          {
            message: `Bucket "${state.name}" has public objects detected in a spot-check sample of ${sampleKeys.length} object(s): ${publicKeys.join(', ')}`,
            remediation: `Make the listed objects private (aws s3api put-object-acl --bucket ${state.name} --key <key> --acl private) and disable ACLs via Object Ownership (BucketOwnerEnforced) to prevent public object ACLs entirely`,
          }
        ));
      }
    } catch (error) {
      logger.debug(`Failed to spot-check objects in bucket ${state.name}`, { error: (error as Error).message });
    }

    return findings;
  }

  // ---------------------------------------------------------------------------
  // Ported Prowler checks (account level / cross bucket / access points)
  // ---------------------------------------------------------------------------

  private async getAccountPublicAccessBlock(accountId: string | null): Promise<PublicAccessBlockState | null> {
    if (!accountId) return null;
    const account: string = accountId;

    try {
      const result: any = await retry(async () => {
        try {
          return await this.s3control.send(new GetAccountPublicAccessBlockCommand({ AccountId: account }));
        } catch (error) {
          if (this.isErrorCode(error, 'NoSuchPublicAccessBlockConfiguration')) return null;
          throw error;
        }
      });
      if (result === null) {
        return { blockPublicAcls: false, ignorePublicAcls: false, blockPublicPolicy: false, restrictPublicBuckets: false };
      }
      const config: any = result.PublicAccessBlockConfiguration ?? {};
      return {
        blockPublicAcls: !!config.BlockPublicAcls,
        ignorePublicAcls: !!config.IgnorePublicAcls,
        blockPublicPolicy: !!config.BlockPublicPolicy,
        restrictPublicBuckets: !!config.RestrictPublicBuckets,
      };
    } catch (error) {
      logger.debug('Failed to get account-level public access block', { error: (error as Error).message });
      return null;
    }
  }

  private checkAccountLevelPublicAccessBlocks(
    accountPab: PublicAccessBlockState | null,
    accountId: string | null,
    bucketCount: number
  ): ScanningResult[] {
    const findings: ScanningResult[] = [];

    if (!accountPab || !accountId) return findings;
    // Prowler only fails this check when the account actually uses S3
    if (bucketCount === 0) return findings;

    if (!(accountPab.ignorePublicAcls && accountPab.restrictPublicBuckets)) {
      findings.push(this.emit(
        's3_account_level_public_access_blocks',
        { accountId, config: accountPab },
        {
          message: `Account ${accountId} does not have S3 Block Public Access configured at the account level (IgnorePublicAcls and RestrictPublicBuckets are required)`,
          remediation: `Enable account-level Block Public Access: aws s3control put-public-access-block --account-id ${accountId} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
        }
      ));
    }

    return findings;
  }

  private checkCrossRegionReplication(states: BucketState[]): ScanningResult[] {
    const findings: ScanningResult[] = [];

    const regionByName = new Map<string, string>();
    for (const state of states) regionByName.set(state.name, state.region);

    for (const state of states) {
      if (state.replicationRules === undefined) continue; // could not read replication config

      const versioningEnabled = state.versioning?.Status === 'Enabled';
      let failReason = 'no enabled cross-region replication rule exists';
      let pass = false;

      for (const rule of state.replicationRules) {
        if (!(versioningEnabled && rule.Status === 'Enabled' && rule.Destination?.Bucket)) continue;
        const destName = String(rule.Destination.Bucket).split(':').pop() ?? '';
        const destRegion = regionByName.get(destName);
        const ruleId = rule.ID ?? 'unnamed';
        if (!destRegion) {
          failReason = `replication rule "${ruleId}" targets bucket "${destName}" outside the scanned account`;
          continue;
        }
        if (destRegion !== state.region) {
          pass = true;
          break;
        }
        failReason = `replication rule "${ruleId}" targets bucket "${destName}" in the same region (${destRegion})`;
      }

      if (!pass) {
        findings.push(this.emit(
          's3_bucket_cross_region_replication',
          { bucket: state.name, region: state.region, versioningEnabled, replicationRules: state.replicationRules.length },
          {
            message: `Bucket "${state.name}" does not have correct cross-region replication: ${failReason}`,
            remediation: `Enable versioning on bucket "${state.name}" and add an enabled replication rule targeting a bucket in a different AWS region`,
          }
        ));
      }
    }

    return findings;
  }

  private async checkShadowResources(
    states: BucketState[],
    accountId: string | null,
    canonicalId: string
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    if (!accountId) return findings;

    const reported = new Set<string>();
    const ourBucketNames = new Set(states.map((s) => s.name));

    // 1. Buckets in this account whose names match a predictable service pattern
    for (const state of states) {
      for (const { service, pattern } of SHADOW_BUCKET_PATTERNS) {
        const expected = pattern.replace('<account>', accountId).replace('<region>', state.region);
        if (!state.name.startsWith(expected)) continue;
        reported.add(state.name);
        if (canonicalId && state.ownerId && state.ownerId !== canonicalId) {
          findings.push(this.emit(
            's3_bucket_shadow_resource_vulnerability',
            { bucket: state.name, service, ownerId: state.ownerId },
            {
              message: `Bucket "${state.name}" matches the predictable ${service} service bucket name but is owned by another account (owner canonical id ${state.ownerId})`,
              remediation: `Investigate bucket "${state.name}": a bucket matching your account's predictable ${service} name should be owned by this account. Remove any service configuration pointing at it and pre-claim the name yourself.`,
            }
          ));
        }
        break;
      }
    }

    // 2. Probe predictable names in relevant regions for buckets pre-claimed by other accounts
    const regionsToTest = new Set<string>([this.client.getRegion()]);
    for (const state of states) regionsToTest.add(state.region);

    for (const region of regionsToTest) {
      for (const { service, pattern } of SHADOW_BUCKET_PATTERNS) {
        const bucketName = pattern.replace('<account>', accountId).replace('<region>', region);
        if (ourBucketNames.has(bucketName) || reported.has(bucketName)) continue;

        if (await this.shadowBucketExists(bucketName)) {
          reported.add(bucketName);
          findings.push(this.emit(
            's3_bucket_shadow_resource_vulnerability',
            { bucket: bucketName, service, region },
            {
              message: `Predictable ${service} service bucket name "${bucketName}" already exists and is owned by another account (shadow resource)`,
              remediation: `The ${service} service bucket name for your account in ${region} has been claimed by another account. Avoid using ${service} defaults in that region and contact AWS Support; pre-claim predictable service bucket names in all regions you plan to use.`,
            }
          ));
        }
      }
    }

    return findings;
  }

  /** True only when the bucket demonstrably exists (200, or 403/301 meaning it exists but is not ours). */
  private async shadowBucketExists(bucketName: string): Promise<boolean> {
    try {
      await this.client.s3.send(new HeadBucketCommand({ Bucket: bucketName }));
      return true;
    } catch (error) {
      const status = (error as any)?.$metadata?.httpStatusCode;
      if (status === 403 || status === 301) return true;
      if (status !== 404 && !this.isErrorCode(error, 'NotFound') && !this.isErrorCode(error, 'NoSuchBucket')) {
        logger.debug(`Could not determine existence of bucket ${bucketName}`, { error: (error as Error).message });
      }
      return false;
    }
  }

  private async scanAccessPoints(accountId: string | null): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    if (!accountId) return findings;
    const account: string = accountId;

    try {
      const accessPoints: any[] = [];
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.s3control.send(new ListAccessPointsCommand({ AccountId: account, NextToken: nextToken }));
        });
        accessPoints.push(...(result.AccessPointList ?? []));
        nextToken = result.NextToken;
      } while (nextToken);

      for (const ap of accessPoints) {
        try {
          const detail: any = await retry(async () => {
            return await this.s3control.send(new GetAccessPointCommand({ AccountId: account, Name: ap.Name }));
          });
          const config: any = detail.PublicAccessBlockConfiguration ?? {};
          if (!(config.BlockPublicAcls && config.IgnorePublicAcls && config.BlockPublicPolicy && config.RestrictPublicBuckets)) {
            findings.push(this.emit(
              's3_access_point_public_access_block',
              { accessPoint: ap.Name, bucket: ap.Bucket, config },
              {
                message: `S3 access point "${ap.Name}" for bucket "${ap.Bucket}" does not have all Block Public Access settings enabled`,
                remediation: `Recreate access point "${ap.Name}" with all four Block Public Access settings enabled (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets); they cannot be changed after creation`,
              }
            ));
          }
        } catch (error) {
          logger.debug(`Failed to get S3 access point ${ap.Name}`, { error: (error as Error).message });
        }
      }
    } catch (error) {
      logger.debug('Failed to list S3 access points', { error: (error as Error).message });
    }

    return findings;
  }

  private async scanMultiRegionAccessPoints(accountId: string | null): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    if (!accountId) return findings;
    const account: string = accountId;

    // The Multi-Region Access Point control-plane API is only served from us-west-2
    const mrapClient = new S3ControlClient({ ...this.client.getClientConfig(), region: 'us-west-2' });
    try {
      const accessPoints: any[] = [];
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await mrapClient.send(new ListMultiRegionAccessPointsCommand({ AccountId: account, NextToken: nextToken }));
        });
        accessPoints.push(...(result.AccessPoints ?? []));
        nextToken = result.NextToken;
      } while (nextToken);

      for (const mrap of accessPoints) {
        const config: any = mrap.PublicAccessBlock ?? {};
        const buckets: string[] = (mrap.Regions ?? [])
          .map((r: any) => r.Bucket ?? '')
          .filter((b: string) => !!b);
        if (!(config.BlockPublicAcls && config.IgnorePublicAcls && config.BlockPublicPolicy && config.RestrictPublicBuckets)) {
          findings.push(this.emit(
            's3_multi_region_access_point_public_access_block',
            { multiRegionAccessPoint: mrap.Name, buckets, config },
            {
              message: `S3 Multi-Region Access Point "${mrap.Name}" (buckets: ${buckets.join(', ')}) does not have all Block Public Access settings enabled`,
              remediation: `Recreate Multi-Region Access Point "${mrap.Name}" with all Block Public Access settings enabled; MRAP public access settings are immutable after creation`,
            }
          ));
        }
      }
    } catch (error) {
      logger.debug('Failed to list S3 multi-region access points', { error: (error as Error).message });
    } finally {
      mrapClient.destroy();
    }

    return findings;
  }

  // ---------------------------------------------------------------------------
  // Policy analysis helpers
  // ---------------------------------------------------------------------------

  private toArray(value: any): any[] {
    if (value === undefined || value === null) return [];
    return Array.isArray(value) ? value : [value];
  }

  private hasPolicyStatements(policy: any): boolean {
    return !!policy && typeof policy === 'object' && this.toArray(policy.Statement).length > 0;
  }

  /** True when a statement's conditions scope the grant to specific accounts/orgs/networks. */
  private statementHasRestrictiveCondition(stmt: any): boolean {
    const condition = stmt.Condition ?? {};
    for (const operator of Object.keys(condition)) {
      for (const key of Object.keys(condition[operator] ?? {})) {
        if (RESTRICTIVE_CONDITION_KEYS.includes(key.toLowerCase())) return true;
      }
    }
    return false;
  }

  private getAwsPrincipals(stmt: any): string[] {
    const principal = stmt.Principal;
    if (principal === '*') return ['*'];
    if (principal && typeof principal === 'object') {
      return this.toArray(principal.AWS).map((p: any) => String(p));
    }
    return [];
  }

  private policyAllowsCrossAccountAccess(policy: any, accountId: string): { principal: string } | null {
    for (const stmt of this.toArray(policy.Statement)) {
      if (stmt.Effect !== 'Allow' || this.statementHasRestrictiveCondition(stmt)) continue;
      for (const principal of this.getAwsPrincipals(stmt)) {
        if (principal === '*') return { principal };
        let principalAccount = '';
        if (principal.startsWith('arn:')) {
          principalAccount = principal.split(':')[4] ?? '';
        } else if (/^\d{12}$/.test(principal)) {
          principalAccount = principal;
        }
        if (principalAccount && principalAccount !== accountId) return { principal };
      }
    }
    return null;
  }

  private policyAllowsPublicWrite(policy: any): { action: string } | null {
    for (const stmt of this.toArray(policy.Statement)) {
      if (stmt.Effect !== 'Allow' || this.statementHasRestrictiveCondition(stmt)) continue;
      if (!this.getAwsPrincipals(stmt).includes('*')) continue;
      for (const rawAction of this.toArray(stmt.Action)) {
        const action = String(rawAction).toLowerCase();
        if (action === '*' || action === 's3:*') return { action: String(rawAction) };
        if (action.endsWith('*')) {
          const prefix = action.slice(0, -1);
          if (PUBLIC_WRITE_ACTIONS.some((write) => write.startsWith(prefix))) return { action: String(rawAction) };
        } else if (PUBLIC_WRITE_ACTIONS.includes(action)) {
          return { action: String(rawAction) };
        }
      }
    }
    return null;
  }
}

export default S3Scanner;
