// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  SSMIncidentsClient,
  ListReplicationSetsCommand,
  ListResponsePlansCommand,
} from '@aws-sdk/client-ssm-incidents';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class SSMIncidentsScanner extends BaseScanner {
  private incidents: SSMIncidentsClient;

  constructor(client: AWSClient) {
    super(client, 'SSMIncidents');
    this.incidents = new SSMIncidentsClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Incident Manager security scan...');

      // ssmincidents_enabled_with_plans: Incident Manager should have a
      // replication set and at least one response plan ready.
      const replication: any = await retry(async () => {
        return await this.incidents.send(new ListReplicationSetsCommand({}));
      });
      const replicationSets: string[] = replication.replicationSetArns ?? [];

      if (replicationSets.length === 0) {
        findings.push(this.emit(
          'ssmincidents_enabled_with_plans',
          { replicationSets: 0, responsePlans: 0 },
          {
            message: 'AWS Incident Manager is not enabled (no replication set exists), so there is no prepared incident response capability',
            remediation: 'Enable Incident Manager by creating a replication set, then create response plans for critical incident scenarios',
          }
        ));
      } else {
        const plans: any = await retry(async () => {
          return await this.incidents.send(new ListResponsePlansCommand({}));
        });
        if ((plans.responsePlanSummaries ?? []).length === 0) {
          findings.push(this.emit(
            'ssmincidents_enabled_with_plans',
            { replicationSets: replicationSets.length, responsePlans: 0 },
            {
              message: 'AWS Incident Manager is enabled but has no response plans, so incidents cannot be handled through prepared runbooks',
              remediation: 'Create Incident Manager response plans covering your critical incident scenarios',
            }
          ));
        }
      }

      logger.info(`SSMIncidents scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('SSMIncidents scan failed', { error: (error as Error).message });
    }

    return findings;
  }
}

export default SSMIncidentsScanner;
