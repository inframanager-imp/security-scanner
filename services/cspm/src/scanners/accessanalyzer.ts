// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  AccessAnalyzerClient,
  ListAnalyzersCommand,
  ListFindingsCommand,
} from '@aws-sdk/client-accessanalyzer';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class AccessAnalyzerScanner extends BaseScanner {
  private analyzer: AccessAnalyzerClient;

  constructor(client: AWSClient) {
    super(client, 'AccessAnalyzer');
    this.analyzer = new AccessAnalyzerClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Access Analyzer security scan...');

      const analyzers = await this.listAnalyzers();
      logger.info(`AccessAnalyzer: scanning ${analyzers.length} analyzer(s)`);

      for (const analyzer of analyzers) {
        try {
          if (analyzer.status !== 'ACTIVE') continue;

          // accessanalyzer_enabled_without_findings: an active analyzer should
          // have no active findings — active findings mean resources are shared
          // externally and unreviewed.
          const activeFindings = await this.countActiveFindings(analyzer.arn);
          if (activeFindings > 0) {
            findings.push(this.emit(
              'accessanalyzer_enabled_without_findings',
              { analyzer: analyzer.name, arn: analyzer.arn, activeFindings },
              {
                message: `IAM Access Analyzer "${analyzer.name}" has ${activeFindings} active finding(s) indicating externally shared resources that have not been reviewed`,
                remediation: `Review the active findings of analyzer "${analyzer.name}" and archive them once the external access is confirmed as intended, or remediate the unintended sharing`,
              }
            ));
          }
        } catch (error) {
          logger.debug(`Failed to scan analyzer ${analyzer.name}`, { error: (error as Error).message });
        }
      }

      logger.info(`AccessAnalyzer scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('AccessAnalyzer scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listAnalyzers(): Promise<any[]> {
    const analyzers: any[] = [];
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.analyzer.send(new ListAnalyzersCommand({ nextToken }));
      });
      analyzers.push(...(result.analyzers ?? []));
      nextToken = result.nextToken;
    } while (nextToken);
    return analyzers;
  }

  private async countActiveFindings(analyzerArn: string): Promise<number> {
    let count = 0;
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.analyzer.send(new ListFindingsCommand({
          analyzerArn,
          filter: { status: { eq: ['ACTIVE'] } },
          nextToken,
        }));
      });
      count += (result.findings ?? []).length;
      nextToken = result.nextToken;
    } while (nextToken);
    return count;
  }
}

export default AccessAnalyzerScanner;
