// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  WellArchitectedClient,
  ListWorkloadsCommand,
} from '@aws-sdk/client-wellarchitected';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class WellArchitectedScanner extends BaseScanner {
  private wa: WellArchitectedClient;

  constructor(client: AWSClient) {
    super(client, 'WellArchitected');
    this.wa = new WellArchitectedClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Well-Architected security scan...');

      const workloads = await this.listWorkloads();
      logger.info(`WellArchitected: scanning ${workloads.length} workload(s)`);

      // wellarchitected_workload_no_high_or_medium_risks: reviewed workloads
      // should carry no unresolved HIGH or MEDIUM risk items.
      for (const workload of workloads) {
        const high = workload.RiskCounts?.HIGH ?? 0;
        const medium = workload.RiskCounts?.MEDIUM ?? 0;
        if (high > 0 || medium > 0) {
          findings.push(this.emit(
            'wellarchitected_workload_no_high_or_medium_risks',
            { workload: workload.WorkloadName, workloadId: workload.WorkloadId, highRisks: high, mediumRisks: medium },
            {
              message: `Well-Architected workload "${workload.WorkloadName}" has ${high} high and ${medium} medium unresolved risk(s)`,
              remediation: `Address the improvement plan items for workload "${workload.WorkloadName}" until no high or medium risks remain`,
            }
          ));
        }
      }

      logger.info(`WellArchitected scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('WellArchitected scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listWorkloads(): Promise<any[]> {
    const workloads: any[] = [];
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.wa.send(new ListWorkloadsCommand({ NextToken: nextToken }));
      });
      workloads.push(...(result.WorkloadSummaries ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return workloads;
  }
}

export default WellArchitectedScanner;
