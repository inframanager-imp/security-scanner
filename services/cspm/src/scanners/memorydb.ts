// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { MemoryDBClient, DescribeClustersCommand } from '@aws-sdk/client-memorydb';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class MemoryDBScanner extends BaseScanner {
  private memorydb: MemoryDBClient;

  constructor(client: AWSClient) {
    super(client, 'MemoryDB');
    this.memorydb = new MemoryDBClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting MemoryDB security scan...');

      const clusters = await this.listClusters();
      for (const cluster of clusters) {
        const clusterName: string = cluster.Name ?? '';
        logger.debug(`Scanning MemoryDB cluster: ${clusterName}`);
        try {
          // memorydb_cluster_auto_minor_version_upgrades
          if (!(cluster.AutoMinorVersionUpgrade ?? false)) {
            findings.push(this.emit(
              'memorydb_cluster_auto_minor_version_upgrades',
              { cluster: clusterName, arn: cluster.ARN ?? '', autoMinorVersionUpgrade: false },
              {
                message: `MemoryDB cluster "${clusterName}" does not have automatic minor version upgrades enabled`,
              }
            ));
          }
        } catch (error) {
          logger.debug(`Failed to scan MemoryDB cluster ${clusterName}`, { error: (error as Error).message });
        }
      }

      logger.info(`MemoryDB scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('MemoryDB scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listClusters(): Promise<any[]> {
    const clusters: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.memorydb.send(new DescribeClustersCommand({ NextToken: nextToken }));
      });
      clusters.push(...(result.Clusters ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return clusters;
  }
}

export default MemoryDBScanner;
