// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  SecurityHubClient,
  DescribeHubCommand,
  GetEnabledStandardsCommand,
  ListOrganizationAdminAccountsCommand,
} from '@aws-sdk/client-securityhub';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class SecurityHubScanner extends BaseScanner {
  private hub: SecurityHubClient;

  constructor(client: AWSClient) {
    super(client, 'SecurityHub');
    this.hub = new SecurityHubClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Security Hub security scan...');

      const region = this.client.getClientConfig().region as string;

      // securityhub_enabled: hub must be enabled with at least one standard subscribed
      let hubEnabled = false;
      try {
        await retry(async () => await this.hub.send(new DescribeHubCommand({})));
        hubEnabled = true;
      } catch (error) {
        const name = (error as Error).name ?? '';
        if (name === 'InvalidAccessException' || name === 'ResourceNotFoundException') {
          findings.push(this.emit(
            'securityhub_enabled',
            { region, enabled: false },
            {
              message: `AWS Security Hub is not enabled in region ${region}`,
              remediation: `Enable Security Hub in region ${region} and subscribe at least one security standard (e.g. AWS Foundational Security Best Practices)`,
            }
          ));
        } else {
          logger.debug('DescribeHub failed', { error: (error as Error).message });
        }
      }

      if (hubEnabled) {
        try {
          const standards: any = await retry(async () => {
            return await this.hub.send(new GetEnabledStandardsCommand({}));
          });
          if ((standards.StandardsSubscriptions ?? []).length === 0) {
            findings.push(this.emit(
              'securityhub_enabled',
              { region, enabled: true, enabledStandards: 0 },
              {
                message: `AWS Security Hub is enabled in region ${region} but has no security standards subscribed`,
                remediation: `Subscribe at least one Security Hub standard (e.g. AWS Foundational Security Best Practices) in region ${region}`,
              }
            ));
          }
        } catch (error) {
          logger.debug('GetEnabledStandards failed', { error: (error as Error).message });
        }

        // securityhub_delegated_admin_enabled_all_regions: an organization
        // delegated administrator should be registered for Security Hub.
        try {
          const admins: any = await retry(async () => {
            return await this.hub.send(new ListOrganizationAdminAccountsCommand({}));
          });
          const enabledAdmin = (admins.AdminAccounts ?? []).find((a: any) => a.Status === 'ENABLED');
          if (!enabledAdmin) {
            findings.push(this.emit(
              'securityhub_delegated_admin_enabled_all_regions',
              { region, adminAccounts: admins.AdminAccounts ?? [] },
              {
                message: `Security Hub in region ${region} has no enabled organization delegated administrator account`,
                remediation: 'Register a delegated administrator account for Security Hub from the organization management account, in every active region',
              }
            ));
          }
        } catch (error) {
          // AccessDenied is expected for non-management member accounts
          logger.debug('ListOrganizationAdminAccounts failed', { error: (error as Error).message });
        }
      }

      logger.info(`SecurityHub scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('SecurityHub scan failed', { error: (error as Error).message });
    }

    return findings;
  }
}

export default SecurityHubScanner;
