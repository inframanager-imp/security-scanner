// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  DrsClient,
  DescribeJobsCommand,
} from '@aws-sdk/client-drs';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class DRSScanner extends BaseScanner {
  private drs: DrsClient;

  constructor(client: AWSClient) {
    super(client, 'DRS');
    this.drs = new DrsClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting DRS security scan...');

      // drs_job_exist: DRS must be initialized in the region and have at least one
      // recovery/drill job. UninitializedAccountException => DRS disabled.
      try {
        const jobs = await this.describeJobs();
        if (jobs.length === 0) {
          findings.push(this.emit(
            'drs_job_exist',
            { drsStatus: 'ENABLED', jobCount: 0 },
            {
              message: 'DRS is enabled for this region without jobs',
              remediation: 'Add source servers to Elastic Disaster Recovery and run a recovery drill so at least one recovery job exists, validating that failover works',
            }
          ));
        }
      } catch (error) {
        if ((error as Error).name === 'UninitializedAccountException') {
          findings.push(this.emit(
            'drs_job_exist',
            { drsStatus: 'DISABLED', jobCount: 0 },
            {
              message: 'DRS is not enabled for this region',
            }
          ));
        } else {
          throw error;
        }
      }

      logger.info(`DRS scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('DRS scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async describeJobs(): Promise<any[]> {
    const jobs: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.drs.send(new DescribeJobsCommand({ nextToken }));
      });
      jobs.push(...(result.items ?? []));
      nextToken = result.nextToken;
    } while (nextToken);
    return jobs;
  }
}

export default DRSScanner;
