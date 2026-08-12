// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  DLMClient,
  GetLifecyclePoliciesCommand,
} from '@aws-sdk/client-dlm';
import {
  EC2Client,
  DescribeSnapshotsCommand,
} from '@aws-sdk/client-ec2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class DLMScanner extends BaseScanner {
  private dlm: DLMClient;
  private ec2: EC2Client;

  constructor(client: AWSClient) {
    super(client, 'DLM');
    this.dlm = new DLMClient(client.getClientConfig());
    this.ec2 = new EC2Client(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting DLM security scan...');

      // dlm_ebs_snapshot_lifecycle_policy_exists: only evaluated in regions that
      // contain self-owned EBS snapshots (mirrors Prowler's regions_with_snapshots gate)
      const hasSnapshots = await this.regionHasSelfOwnedSnapshots();
      if (hasSnapshots) {
        const policies = await this.getLifecyclePolicies();
        if (policies.length === 0) {
          findings.push(this.emit(
            'dlm_ebs_snapshot_lifecycle_policy_exists',
            { selfOwnedSnapshotsPresent: true, lifecyclePolicyCount: 0 },
            {
              message: 'No EBS Snapshot lifecycle policies found in a region that contains self-owned EBS snapshots',
            }
          ));
        }
      }

      logger.info(`DLM scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('DLM scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async regionHasSelfOwnedSnapshots(): Promise<boolean> {
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.ec2.send(new DescribeSnapshotsCommand({
          OwnerIds: ['self'],
          MaxResults: 5,
          NextToken: nextToken,
        }));
      });
      if ((result.Snapshots ?? []).length > 0) {
        return true;
      }
      nextToken = result.NextToken;
    } while (nextToken);
    return false;
  }

  private async getLifecyclePolicies(): Promise<any[]> {
    const result = await retry(async () => {
      return await this.dlm.send(new GetLifecyclePoliciesCommand({}));
    });
    return result.Policies ?? [];
  }
}

export default DLMScanner;
