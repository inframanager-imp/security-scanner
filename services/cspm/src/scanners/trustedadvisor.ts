// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  SupportClient,
  DescribeServicesCommand,
  DescribeTrustedAdvisorChecksCommand,
  DescribeTrustedAdvisorCheckSummariesCommand,
} from '@aws-sdk/client-support';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class TrustedAdvisorScanner extends BaseScanner {
  private support: SupportClient;

  constructor(client: AWSClient) {
    super(client, 'TrustedAdvisor');
    // Support API is a global service hosted in us-east-1
    this.support = new SupportClient({ ...client.getClientConfig(), region: 'us-east-1' });
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Trusted Advisor security scan...');

      // trustedadvisor_premium_support_plan_subscribed: DescribeServices only
      // succeeds with a Business, Enterprise On-Ramp or Enterprise support plan
      let premiumSupport = false;
      try {
        await this.support.send(new DescribeServicesCommand({}));
        premiumSupport = true;
      } catch (error) {
        const err = error as any;
        if (String(err?.name ?? '').includes('SubscriptionRequired')) {
          findings.push(this.emit(
            'trustedadvisor_premium_support_plan_subscribed',
            { region: 'us-east-1', premiumSupportEnabled: false },
            {
              message: 'AWS account is not subscribed to a Premium Support plan (Business, Enterprise On-Ramp or Enterprise)',
            }
          ));
        } else {
          // AccessDenied or other failure: the support plan cannot be determined
          // (mirrors Prowler setting premium_support to None — no finding)
          logger.debug('Unable to determine AWS support plan', { error: err?.message });
        }
      }

      if (!premiumSupport) {
        // Without premium support the Trusted Advisor APIs below are unavailable
        logger.info(`TrustedAdvisor scan complete. Found ${findings.length} findings.`);
        return findings;
      }

      let checks: any[] = [];
      try {
        const result: any = await retry(async () => {
          return await this.support.send(new DescribeTrustedAdvisorChecksCommand({ language: 'en' }));
        });
        checks = result.checks ?? [];
      } catch (error) {
        // SubscriptionRequiredException: account has no Business/Enterprise support plan
        logger.debug('Trusted Advisor unavailable (support plan required?)', { error: (error as Error).message });
        return findings;
      }

      // trustedadvisor_errors_and_warnings: no check should be in error/warning state
      for (let i = 0; i < checks.length; i += 100) {
        const batch = checks.slice(i, i + 100);
        const summaries: any = await retry(async () => {
          return await this.support.send(new DescribeTrustedAdvisorCheckSummariesCommand({
            checkIds: batch.map((c: any) => c.id),
          }));
        });
        for (const summary of summaries.summaries ?? []) {
          if (summary.status !== 'error' && summary.status !== 'warning') continue;
          const check = batch.find((c: any) => c.id === summary.checkId);
          findings.push(this.emit(
            'trustedadvisor_errors_and_warnings',
            {
              checkId: summary.checkId,
              checkName: check?.name,
              category: check?.category,
              status: summary.status,
              flaggedResources: summary.resourcesSummary?.resourcesFlagged ?? 0,
            },
            {
              message: `Trusted Advisor check "${check?.name ?? summary.checkId}" reports status "${summary.status}" with ${summary.resourcesSummary?.resourcesFlagged ?? 0} flagged resource(s)`,
              remediation: `Open Trusted Advisor and remediate the resources flagged by "${check?.name ?? summary.checkId}"`,
            }
          ));
        }
      }

      logger.info(`TrustedAdvisor scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('TrustedAdvisor scan failed', { error: (error as Error).message });
    }

    return findings;
  }
}

export default TrustedAdvisorScanner;
