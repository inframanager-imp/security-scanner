// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  EFSClient,
  DescribeFileSystemsCommand,
  DescribeBackupPolicyCommand,
  DescribeFileSystemPolicyCommand,
  DescribeMountTargetsCommand,
  DescribeAccessPointsCommand,
} from '@aws-sdk/client-efs';
import { DescribeSubnetsCommand } from '@aws-sdk/client-ec2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

/** Condition keys that scope a statement enough that it is not considered public. */
const RESTRICTIVE_CONDITION_KEYS = [
  'aws:sourceip',
  'aws:sourcevpc',
  'aws:sourcevpce',
  'aws:sourceaccount',
  'aws:sourcearn',
  'aws:sourceowner',
  'aws:principalorgid',
  'aws:principalaccount',
  'aws:principalarn',
];

function hasPublicPrincipal(statement: any): boolean {
  const principal = statement?.Principal;
  if (principal === '*') return true;
  if (principal && typeof principal === 'object') {
    const aws = principal.AWS;
    if (aws === '*') return true;
    if (Array.isArray(aws) && aws.includes('*')) return true;
    const canonicalUser = principal.CanonicalUser;
    if (canonicalUser === '*') return true;
    if (Array.isArray(canonicalUser) && canonicalUser.includes('*')) return true;
  }
  return false;
}

function hasRestrictiveCondition(statement: any): boolean {
  const condition = statement?.Condition;
  if (!condition || typeof condition !== 'object') return false;
  for (const operatorValue of Object.values(condition)) {
    if (operatorValue && typeof operatorValue === 'object') {
      for (const key of Object.keys(operatorValue as object)) {
        if (RESTRICTIVE_CONDITION_KEYS.includes(key.toLowerCase())) return true;
      }
    }
  }
  return false;
}

/** Simplified port of Prowler's is_policy_public(): Allow + wildcard principal + no scoping condition. */
function isPolicyPublic(policy: any): boolean {
  const rawStatements = policy?.Statement;
  const statements: any[] = Array.isArray(rawStatements) ? rawStatements : rawStatements ? [rawStatements] : [];
  return statements.some(
    (s) => s?.Effect === 'Allow' && hasPublicPrincipal(s) && !hasRestrictiveCondition(s)
  );
}

export class EFSScanner extends BaseScanner {
  private efs: EFSClient;

  constructor(client: AWSClient) {
    super(client, 'EFS');
    this.efs = new EFSClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting EFS security scan...');

      const fileSystems = await this.listFileSystems();
      for (const fs of fileSystems) {
        const fsId = fs.FileSystemId || 'Unknown';
        logger.debug(`Scanning EFS file system: ${fsId}`);

        // efs_encryption_at_rest_enabled
        if (fs.Encrypted !== true) {
          findings.push(this.emit(
            'efs_encryption_at_rest_enabled',
            { fileSystemId: fsId, encrypted: fs.Encrypted ?? false },
            {
              message: `EFS file system "${fsId}" does not have encryption at rest enabled`,
              remediation: `Create a new encrypted file system and migrate data from "${fsId}"; encryption cannot be enabled on an existing unencrypted file system`,
            }
          ));
        }

        // efs_multi_az_enabled
        if (fs.AvailabilityZoneId) {
          findings.push(this.emit(
            'efs_multi_az_enabled',
            { fileSystemId: fsId, availabilityZoneId: fs.AvailabilityZoneId },
            { message: `EFS file system "${fsId}" is a Single-AZ (One Zone) file system` }
          ));
        } else if ((fs.NumberOfMountTargets ?? 0) <= 1) {
          findings.push(this.emit(
            'efs_multi_az_enabled',
            { fileSystemId: fsId, numberOfMountTargets: fs.NumberOfMountTargets ?? 0 },
            { message: `EFS file system "${fsId}" is a Regional file system but has only ${fs.NumberOfMountTargets ?? 0} mount target(s)` }
          ));
        }

        const backupFindings = await this.checkBackupPolicy(fsId);
        findings.push(...backupFindings);

        const policyFindings = await this.checkFileSystemPolicy(fsId);
        findings.push(...policyFindings);

        const mountTargetFindings = await this.checkMountTargets(fsId);
        findings.push(...mountTargetFindings);

        const accessPointFindings = await this.checkAccessPoints(fsId);
        findings.push(...accessPointFindings);
      }

      logger.info(`EFS scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('EFS scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listFileSystems(): Promise<any[]> {
    const fileSystems: any[] = [];
    let marker: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.efs.send(new DescribeFileSystemsCommand({ Marker: marker }));
      });
      fileSystems.push(...(result.FileSystems ?? []));
      marker = result.NextMarker;
    } while (marker);
    return fileSystems;
  }

  private async checkBackupPolicy(fsId: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      let backupStatus = 'DISABLED';
      try {
        const result = await retry(async () => {
          return await this.efs.send(new DescribeBackupPolicyCommand({ FileSystemId: fsId }));
        });
        backupStatus = result.BackupPolicy?.Status ?? 'DISABLED';
      } catch (error) {
        const err = error as any;
        if (err?.name === 'PolicyNotFound' || String(err?.message ?? '').includes('PolicyNotFound')) {
          backupStatus = 'DISABLED';
        } else {
          throw error;
        }
      }

      if (backupStatus === 'DISABLED' || backupStatus === 'DISABLING') {
        findings.push(this.emit(
          'efs_have_backup_enabled',
          { fileSystemId: fsId, backupPolicyStatus: backupStatus },
          { message: `EFS file system "${fsId}" does not have automatic backups enabled` }
        ));
      }
    } catch (error) {
      logger.debug(`Failed to check backup policy for EFS ${fsId}`, { error: (error as Error).message });
    }
    return findings;
  }

  private async checkFileSystemPolicy(fsId: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      let policy: any = null;
      let hasPolicy = true;
      try {
        const result = await retry(async () => {
          return await this.efs.send(new DescribeFileSystemPolicyCommand({ FileSystemId: fsId }));
        });
        if (result.Policy) {
          policy = JSON.parse(result.Policy);
        } else {
          hasPolicy = false;
        }
      } catch (error) {
        const err = error as any;
        if (err?.name === 'PolicyNotFound' || String(err?.message ?? '').includes('PolicyNotFound')) {
          hasPolicy = false;
        } else {
          throw error;
        }
      }

      if (!hasPolicy || !policy) {
        findings.push(this.emit(
          'efs_not_publicly_accessible',
          { fileSystemId: fsId, hasPolicy: false },
          {
            message: `EFS file system "${fsId}" has no file system policy, which grants full access to any client within the VPC`,
            remediation: `Attach a least-privilege file system policy to "${fsId}" requiring the elasticfilesystem:AccessedViaMountTarget=true condition`,
          }
        ));
      } else {
        const rawStatements = policy.Statement;
        const statements: any[] = Array.isArray(rawStatements) ? rawStatements : rawStatements ? [rawStatements] : [];
        const someStatementUnscoped = statements.some(
          (stmt) => stmt?.Condition?.Bool?.['elasticfilesystem:AccessedViaMountTarget'] !== 'true'
        );
        if (isPolicyPublic(policy) && someStatementUnscoped) {
          findings.push(this.emit(
            'efs_not_publicly_accessible',
            { fileSystemId: fsId, hasPolicy: true, policy },
            { message: `EFS file system "${fsId}" has a policy that allows access to any client within the VPC` }
          ));
        }
      }
    } catch (error) {
      logger.debug(`Failed to check file system policy for EFS ${fsId}`, { error: (error as Error).message });
    }
    return findings;
  }

  private async checkMountTargets(fsId: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const mountTargets: any[] = [];
      let marker: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.efs.send(new DescribeMountTargetsCommand({ FileSystemId: fsId, Marker: marker }));
        });
        mountTargets.push(...(result.MountTargets ?? []));
        marker = result.NextMarker;
      } while (marker);

      if (mountTargets.length === 0) return findings;

      const subnetIds = [...new Set(mountTargets.map((mt) => mt.SubnetId).filter((s) => !!s))] as string[];
      if (subnetIds.length === 0) return findings;

      const subnetsResult = await retry(async () => {
        return await this.client.ec2.send(new DescribeSubnetsCommand({ SubnetIds: subnetIds }));
      });
      const publicSubnetIds = new Set(
        (subnetsResult.Subnets ?? [])
          .filter((subnet: any) => subnet.MapPublicIpOnLaunch === true)
          .map((subnet: any) => subnet.SubnetId)
      );

      const publicMountTargets = mountTargets.filter((mt) => publicSubnetIds.has(mt.SubnetId));
      if (publicMountTargets.length > 0) {
        findings.push(this.emit(
          'efs_mount_target_not_publicly_accessible',
          {
            fileSystemId: fsId,
            publicMountTargets: publicMountTargets.map((mt) => ({ mountTargetId: mt.MountTargetId, subnetId: mt.SubnetId })),
          },
          {
            message: `EFS file system "${fsId}" has mount targets in public subnets: ${publicMountTargets.map((mt) => mt.MountTargetId).join(', ')}`,
          }
        ));
      }
    } catch (error) {
      logger.debug(`Failed to check mount targets for EFS ${fsId}`, { error: (error as Error).message });
    }
    return findings;
  }

  private async checkAccessPoints(fsId: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const accessPoints: any[] = [];
      let nextToken: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.efs.send(new DescribeAccessPointsCommand({ FileSystemId: fsId, NextToken: nextToken }));
        });
        accessPoints.push(...(result.AccessPoints ?? []));
        nextToken = result.NextToken;
      } while (nextToken);

      // Prowler only evaluates these two checks when the file system has access points
      if (accessPoints.length === 0) return findings;

      // efs_access_point_enforce_root_directory
      const rootAccessPoints = accessPoints.filter((ap) => ap.RootDirectory?.Path === '/');
      if (rootAccessPoints.length > 0) {
        findings.push(this.emit(
          'efs_access_point_enforce_root_directory',
          { fileSystemId: fsId, accessPoints: rootAccessPoints.map((ap) => ap.AccessPointId) },
          {
            message: `EFS file system "${fsId}" has access points that allow access to the root directory: ${rootAccessPoints.map((ap) => ap.AccessPointId).join(', ')}`,
          }
        ));
      }

      // efs_access_point_enforce_user_identity
      const noPosixUserAccessPoints = accessPoints.filter(
        (ap) => !ap.PosixUser || Object.keys(ap.PosixUser).length === 0
      );
      if (noPosixUserAccessPoints.length > 0) {
        findings.push(this.emit(
          'efs_access_point_enforce_user_identity',
          { fileSystemId: fsId, accessPoints: noPosixUserAccessPoints.map((ap) => ap.AccessPointId) },
          {
            message: `EFS file system "${fsId}" has access points with no POSIX user defined: ${noPosixUserAccessPoints.map((ap) => ap.AccessPointId).join(', ')}`,
          }
        ));
      }
    } catch (error) {
      logger.debug(`Failed to check access points for EFS ${fsId}`, { error: (error as Error).message });
    }
    return findings;
  }
}

export default EFSScanner;
