// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  AthenaClient,
  ListWorkGroupsCommand,
  GetWorkGroupCommand,
  ListQueryExecutionsCommand,
} from '@aws-sdk/client-athena';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const VALID_ENCRYPTION_OPTIONS = ['SSE_S3', 'SSE_KMS', 'CSE_KMS'];

export class AthenaScanner extends BaseScanner {
  private athena: AthenaClient;

  constructor(client: AWSClient) {
    super(client, 'Athena');
    this.athena = new AthenaClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Athena security scan...');

      const workgroups = await this.listWorkGroups();
      logger.info(`Athena: scanning ${workgroups.length} workgroup(s)`);

      for (const workgroup of workgroups) {
        try {
          findings.push(...(await this.validateWorkGroup(workgroup)));
        } catch (error) {
          logger.debug(`Failed to scan Athena workgroup ${workgroup.Name}`, { error: (error as Error).message });
        }
      }

      logger.info(`Athena scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Athena scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listWorkGroups(): Promise<any[]> {
    const workgroups: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.athena.send(new ListWorkGroupsCommand({ NextToken: nextToken }));
      });
      workgroups.push(...(result.WorkGroups ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return workgroups;
  }

  private async validateWorkGroup(workgroupSummary: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const name: string = workgroupSummary.Name ?? '';
    if (!name) return findings;

    // Prowler only evaluates enabled workgroups that have recent query activity
    if (workgroupSummary.State !== 'ENABLED') return findings;
    const hasQueries = await this.hasQueryExecutions(name);
    if (!hasQueries) return findings;

    const result = await retry(async () => {
      return await this.athena.send(new GetWorkGroupCommand({ WorkGroup: name }));
    });
    const configuration: any = result.WorkGroup?.Configuration ?? {};

    // athena_workgroup_encryption: query results must be encrypted at rest
    const encryptionOption: string =
      configuration.ResultConfiguration?.EncryptionConfiguration?.EncryptionOption ?? '';
    if (!VALID_ENCRYPTION_OPTIONS.includes(encryptionOption)) {
      findings.push(this.emit(
        'athena_workgroup_encryption',
        { workgroup: name, encryptionOption: encryptionOption || null },
        {
          message: `Athena workgroup "${name}" does not encrypt the query results`,
          remediation: `Enable result encryption (SSE_KMS or CSE_KMS preferred) on workgroup "${name}" and enforce the workgroup configuration`,
        }
      ));
    }

    // athena_workgroup_enforce_configuration: workgroup settings must not be client-overridable
    if (!configuration.EnforceWorkGroupConfiguration) {
      findings.push(this.emit(
        'athena_workgroup_enforce_configuration',
        { workgroup: name, enforceWorkGroupConfiguration: false },
        {
          message: `Athena workgroup "${name}" does not enforce the workgroup configuration, so it can be overridden by client-side settings`,
          remediation: `Set EnforceWorkGroupConfiguration=true on workgroup "${name}" so client-side settings cannot override it`,
        }
      ));
    }

    // athena_workgroup_logging_enabled: CloudWatch metrics/logging must be published
    if (!configuration.PublishCloudWatchMetricsEnabled) {
      findings.push(this.emit(
        'athena_workgroup_logging_enabled',
        { workgroup: name, publishCloudWatchMetricsEnabled: false },
        {
          message: `Athena workgroup "${name}" does not have CloudWatch logging enabled`,
          remediation: `Enable PublishCloudWatchMetricsEnabled on workgroup "${name}" to publish query metrics to CloudWatch`,
        }
      ));
    }

    return findings;
  }

  private async hasQueryExecutions(workgroupName: string): Promise<boolean> {
    try {
      const result = await retry(async () => {
        return await this.athena.send(new ListQueryExecutionsCommand({ WorkGroup: workgroupName }));
      });
      return (result.QueryExecutionIds ?? []).length > 0;
    } catch (error) {
      logger.debug(`Failed to list query executions for Athena workgroup ${workgroupName}`, { error: (error as Error).message });
      return false;
    }
  }
}

export default AthenaScanner;
