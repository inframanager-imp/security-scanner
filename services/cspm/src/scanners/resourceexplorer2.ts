// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  ResourceExplorer2Client,
  ListIndexesCommand,
} from '@aws-sdk/client-resource-explorer-2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class ResourceExplorer2Scanner extends BaseScanner {
  private explorer: ResourceExplorer2Client;

  constructor(client: AWSClient) {
    super(client, 'ResourceExplorer2');
    this.explorer = new ResourceExplorer2Client(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Resource Explorer security scan...');

      // resourceexplorer2_indexes_found: at least one index should exist so
      // resources across the account are discoverable/searchable.
      const indexes: any[] = [];
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.explorer.send(new ListIndexesCommand({ NextToken: nextToken }));
        });
        indexes.push(...(result.Indexes ?? []));
        nextToken = result.NextToken;
      } while (nextToken);

      if (indexes.length === 0) {
        findings.push(this.emit(
          'resourceexplorer2_indexes_found',
          { indexes: 0 },
          {
            message: 'AWS Resource Explorer has no indexes configured, so account-wide resource discovery and search are unavailable',
            remediation: 'Create a Resource Explorer index (and an aggregator index in one region) to enable account-wide resource search',
          }
        ));
      }

      logger.info(`ResourceExplorer2 scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('ResourceExplorer2 scan failed', { error: (error as Error).message });
    }

    return findings;
  }
}

export default ResourceExplorer2Scanner;
