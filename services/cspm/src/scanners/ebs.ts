import {
  DescribeSnapshotsCommand,
  DescribeVolumesCommand,
  GetEbsDefaultKmsKeyIdCommand,
  GetEbsEncryptionByDefaultCommand,
  DescribeSnapshotAttributeCommand,
} from '@aws-sdk/client-ec2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class EBSScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'EBS');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting EBS security scan...');

    await Promise.allSettled([
      this.checkDefaultEncryption().then(f => findings.push(...f)),
      this.checkDefaultEncryptionKey().then(f => findings.push(...f)),
      this.checkUnencryptedVolumes().then(f => findings.push(...f)),
      this.checkPublicSnapshots().then(f => findings.push(...f)),
      this.checkUnencryptedSnapshots().then(f => findings.push(...f)),
    ]);

    logger.info(`EBS scan complete. ${findings.length} findings.`);
    return findings;
  }

  private async checkDefaultEncryptionKey(): Promise<ScanningResult[]> {
    try {
      const result = await retry(() =>
        this.client.ec2.send(new GetEbsDefaultKmsKeyIdCommand({}))
      );
      const keyId = result.KmsKeyId ?? '';
      // AWS-managed default key has alias "alias/aws/ebs" or its key ID; CMK has a custom alias or full ARN
      const usesAwsManagedKey = keyId === 'alias/aws/ebs' ||
        keyId.endsWith(':alias/aws/ebs') ||
        keyId === '';
      if (usesAwsManagedKey) {
        return [this.emit(
          'ebs_default_encryption_aws_managed_key',
          { resourceId: 'ebs::default-kms-key', kmsKeyId: keyId || 'alias/aws/ebs' },
          {
            message: `EBS default encryption is set to the AWS-managed key (alias/aws/ebs). AWS-managed keys cannot be audited via CloudTrail key usage, rotated on a custom schedule, or scoped with a key policy.`,
          }
        )];
      }
    } catch { /* permission denied — skip */ }
    return [];
  }

  private async checkDefaultEncryption(): Promise<ScanningResult[]> {
    try {
      const result = await retry(() =>
        this.client.ec2.send(new GetEbsEncryptionByDefaultCommand({}))
      );
      if (!result.EbsEncryptionByDefault) {
        return [this.emit(
          'ebs_default_encryption_disabled',
          { resourceId: 'ebs::default-encryption', accountLevel: true },
          {
            message: 'EBS encryption by default is not enabled for this region. New EBS volumes and snapshot copies will not be automatically encrypted.',
          }
        )];
      }
    } catch { /* permission denied — skip */ }
    return [];
  }

  private async checkUnencryptedVolumes(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    let nextToken: string | undefined;
    const unencrypted: any[] = [];

    try {
      do {
        const result = await retry(() =>
          this.client.ec2.send(new DescribeVolumesCommand({
            Filters: [{ Name: 'encrypted', Values: ['false'] }],
            NextToken: nextToken,
            MaxResults: 500,
          }))
        );
        unencrypted.push(...(result.Volumes ?? []).filter(v => v.State === 'in-use'));
        nextToken = result.NextToken;
      } while (nextToken);
    } catch { return findings; }

    if (unencrypted.length === 0) return findings;

    // Group by instance (one finding per instance)
    const byInstance = new Map<string, any[]>();
    for (const vol of unencrypted) {
      const instanceId = vol.Attachments?.[0]?.InstanceId ?? 'unattached';
      if (!byInstance.has(instanceId)) byInstance.set(instanceId, []);
      byInstance.get(instanceId)!.push(vol);
    }

    for (const [instanceId, vols] of byInstance) {
      const volIds = vols.map(v => v.VolumeId);
      findings.push(this.emit(
        'ec2_ebs_volume_encryption',
        {
          resourceId: `${instanceId}::unencrypted-volumes`,
          instanceId,
          volumeIds: volIds,
          volumeCount: vols.length,
        },
        {
          message: `${vols.length} unencrypted EBS volume(s) (${volIds.slice(0, 3).join(', ')}${vols.length > 3 ? '...' : ''}) ` +
            `are attached to instance "${instanceId}". Unencrypted volumes expose data at rest.`,
        }
      ));
    }
    return findings;
  }

  private async checkPublicSnapshots(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    let nextToken: string | undefined;

    try {
      do {
        const result = await retry(() =>
          this.client.ec2.send(new DescribeSnapshotsCommand({
            OwnerIds: ['self'],
            Filters: [{ Name: 'status', Values: ['completed'] }],
            NextToken: nextToken,
            MaxResults: 100,
          }))
        );

        for (const snap of result.Snapshots ?? []) {
          if (!snap.SnapshotId) continue;
          // Check if public
          try {
            const attr = await this.client.ec2.send(new DescribeSnapshotAttributeCommand({
              SnapshotId: snap.SnapshotId,
              Attribute: 'createVolumePermission',
            }));
            const isPublic = (attr.CreateVolumePermissions ?? []).some(p => p.Group === 'all');
            if (isPublic) {
              findings.push(this.emit(
                'ec2_ebs_public_snapshot',
                {
                  resourceId:   snap.SnapshotId,
                  snapshotId:   snap.SnapshotId,
                  volumeId:     snap.VolumeId,
                  description:  snap.Description,
                  startTime:    snap.StartTime?.toISOString(),
                  volumeSize:   snap.VolumeSize,
                },
                {
                  message: `EBS snapshot "${snap.SnapshotId}" (${snap.Description ?? 'no description'}) is publicly accessible. ` +
                    `Any AWS account can copy this snapshot and access all data it contains.`,
                  remediation: `Make the snapshot private immediately: ` +
                    `aws ec2 modify-snapshot-attribute --snapshot-id ${snap.SnapshotId} --attribute createVolumePermission --operation-type remove --group-names all`,
                }
              ));
            }
          } catch { /* no permission to read snapshot attributes */ }
        }
        nextToken = result.NextToken;
      } while (nextToken);
    } catch { return findings; }

    return findings;
  }

  private async checkUnencryptedSnapshots(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    let nextToken: string | undefined;
    const unencrypted: any[] = [];

    try {
      do {
        const result = await retry(() =>
          this.client.ec2.send(new DescribeSnapshotsCommand({
            OwnerIds: ['self'],
            Filters: [{ Name: 'encrypted', Values: ['false'] }],
            NextToken: nextToken,
            MaxResults: 500,
          }))
        );
        unencrypted.push(...(result.Snapshots ?? []));
        nextToken = result.NextToken;
      } while (nextToken);
    } catch { return findings; }

    if (unencrypted.length > 0) {
      findings.push(this.emit(
        'ec2_ebs_snapshots_encrypted',
        {
          resourceId: 'ebs::unencrypted-snapshots',
          count: unencrypted.length,
          snapshotIds: unencrypted.slice(0, 5).map(s => s.SnapshotId),
        },
        {
          message: `${unencrypted.length} unencrypted EBS snapshot(s) found. ` +
            `Unencrypted snapshots expose backup data and can be copied by other accounts if made public.`,
        }
      ));
    }
    return findings;
  }
}

export default EBSScanner;
