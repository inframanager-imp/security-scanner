// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  Inspector2Client,
  BatchGetAccountStatusCommand,
  ListFindingsCommand,
} from '@aws-sdk/client-inspector2';
import { DescribeInstancesCommand } from '@aws-sdk/client-ec2';
import { DescribeRepositoriesCommand } from '@aws-sdk/client-ecr';
import { ListFunctionsCommand } from '@aws-sdk/client-lambda';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class Inspector2Scanner extends BaseScanner {
  private inspector: Inspector2Client;

  constructor(client: AWSClient) {
    super(client, 'Inspector2');
    this.inspector = new Inspector2Client(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Inspector2 security scan...');
      const region = this.client.getRegion();
      const accountId = await this.client.getAccountId();
      const resourceId = `inspector2::${region}::${accountId}`;

      let account: any;
      try {
        const statusResult = await retry(async () => {
          return await this.inspector.send(new BatchGetAccountStatusCommand({ accountIds: [accountId] }));
        });
        account = (statusResult.accounts ?? [])[0];
      } catch (error) {
        logger.debug('Inspector2 BatchGetAccountStatus failed', { error: (error as Error).message });
        return findings;
      }
      if (!account) return findings;

      const overallStatus: string = account.state?.status ?? 'DISABLED';
      const resourceState: any = account.resourceState ?? {};

      if (overallStatus !== 'ENABLED') {
        // inspector2_is_enabled: service disabled entirely
        findings.push(
          this.emit(
            'inspector2_is_enabled',
            { resourceId, region, accountId, status: overallStatus },
            { message: `Inspector2 is not enabled in this account in region ${region} (status: ${overallStatus})` },
          ),
        );
      } else {
        // inspector2_is_enabled: per-resource-type coverage. Prowler only flags a
        // resource type when matching resources exist in the region (unused-service gate).
        const [ec2InRegion, ecrInRegion, lambdaInRegion] = await Promise.all([
          this.regionHasEc2Instances(),
          this.regionHasEcrRepositories(),
          this.regionHasLambdaFunctions(),
        ]);

        const failedServices: string[] = [];
        if (resourceState.ec2?.status !== 'ENABLED' && ec2InRegion) failedServices.push('EC2');
        if (resourceState.ecr?.status !== 'ENABLED' && ecrInRegion) failedServices.push('ECR');
        if (resourceState.lambda?.status !== 'ENABLED' && lambdaInRegion) failedServices.push('Lambda');
        if (resourceState.lambdaCode?.status !== 'ENABLED' && lambdaInRegion) failedServices.push('Lambda Code');

        if (failedServices.length > 0) {
          findings.push(
            this.emit(
              'inspector2_is_enabled',
              {
                resourceId,
                region,
                accountId,
                status: overallStatus,
                failedServices,
                ec2Status: resourceState.ec2?.status ?? 'DISABLED',
                ecrStatus: resourceState.ecr?.status ?? 'DISABLED',
                lambdaStatus: resourceState.lambda?.status ?? 'DISABLED',
                lambdaCodeStatus: resourceState.lambdaCode?.status ?? 'DISABLED',
              },
              { message: `Inspector2 is not enabled for the following services: ${failedServices.join(', ')}` },
            ),
          );
        }

        // inspector2_active_findings_exist: only evaluated when Inspector2 is enabled
        try {
          const result = await retry(async () => {
            return await this.inspector.send(new ListFindingsCommand({
              filterCriteria: {
                awsAccountId: [{ comparison: 'EQUALS', value: accountId }],
                findingStatus: [{ comparison: 'EQUALS', value: 'ACTIVE' }],
              },
              maxResults: 1,
            }));
          });
          if ((result.findings ?? []).length > 0) {
            findings.push(
              this.emit(
                'inspector2_active_findings_exist',
                { resourceId, region, accountId, activeFindings: true },
                { message: `Inspector2 has active vulnerability findings in region ${region} that require triage` },
              ),
            );
          }
        } catch (error) {
          logger.debug('Inspector2 ListFindings failed', { error: (error as Error).message });
        }
      }

      logger.info(`Inspector2 scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Inspector2 scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  // Presence probes for the unused-service gate. On probe failure the resource
  // type is treated as absent (matching Prowler, where missing inventory data
  // leaves the gate closed) and the coverage gap is not flagged.

  private async regionHasEc2Instances(): Promise<boolean> {
    try {
      const result = await retry(async () => {
        return await this.client.ec2.send(new DescribeInstancesCommand({ MaxResults: 5 }));
      });
      return (result.Reservations ?? []).some((r: any) => (r.Instances ?? []).length > 0);
    } catch (error) {
      logger.debug('Inspector2: EC2 presence probe failed', { error: (error as Error).message });
      return false;
    }
  }

  private async regionHasEcrRepositories(): Promise<boolean> {
    try {
      const result = await retry(async () => {
        return await this.client.ecr.send(new DescribeRepositoriesCommand({ maxResults: 1 }));
      });
      return (result.repositories ?? []).length > 0;
    } catch (error) {
      logger.debug('Inspector2: ECR presence probe failed', { error: (error as Error).message });
      return false;
    }
  }

  private async regionHasLambdaFunctions(): Promise<boolean> {
    try {
      const result = await retry(async () => {
        return await this.client.lambda.send(new ListFunctionsCommand({ MaxItems: 1 }));
      });
      return (result.Functions ?? []).length > 0;
    } catch (error) {
      logger.debug('Inspector2: Lambda presence probe failed', { error: (error as Error).message });
      return false;
    }
  }
}

export default Inspector2Scanner;
