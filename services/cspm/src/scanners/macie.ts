// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  Macie2Client,
  GetMacieSessionCommand,
  GetAutomatedDiscoveryConfigurationCommand,
} from '@aws-sdk/client-macie2';
import { ListBucketsCommand } from '@aws-sdk/client-s3';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class MacieScanner extends BaseScanner {
  private macie: Macie2Client;

  constructor(client: AWSClient) {
    super(client, 'Macie');
    this.macie = new Macie2Client(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Macie security scan...');
      const region = this.client.getRegion();
      const resourceId = `macie::${region}::session`;

      // Session status: GetMacieSession throws "Macie is not enabled" when the
      // account has never enabled Macie in this region (Prowler treats that as DISABLED).
      let status: string | undefined;
      try {
        const session = await retry(async () => {
          return await this.macie.send(new GetMacieSessionCommand({}));
        });
        status = session.status;
      } catch (error) {
        const message = (error as Error).message ?? '';
        if (message.includes('Macie is not enabled')) {
          status = 'DISABLED';
        } else {
          logger.debug('Macie GetMacieSession failed', { error: message });
          return findings;
        }
      }

      if (status === 'ENABLED') {
        // macie_automated_sensitive_data_discovery_enabled: only evaluated when Macie is enabled
        try {
          const config: any = await retry(async () => {
            return await this.macie.send(new GetAutomatedDiscoveryConfigurationCommand({}));
          });
          const discoveryStatus: string = config.status ?? 'DISABLED';
          if (discoveryStatus !== 'ENABLED') {
            findings.push(
              this.emit(
                'macie_automated_sensitive_data_discovery_enabled',
                { resourceId, region, macieStatus: status, automatedDiscoveryStatus: discoveryStatus },
                { message: `Macie is enabled in region ${region} but automated sensitive data discovery is not enabled (status: ${discoveryStatus})` },
              ),
            );
          }
        } catch (error) {
          logger.debug('Macie GetAutomatedDiscoveryConfiguration failed', { error: (error as Error).message });
        }
      } else {
        // macie_is_enabled: Prowler only flags a disabled/paused session when the
        // account actually stores data in S3; approximate the per-region bucket
        // gate with an account-level bucket presence probe.
        const hasBuckets = await this.accountHasS3Buckets();
        if (hasBuckets) {
          const suspended = status === 'PAUSED';
          findings.push(
            this.emit(
              'macie_is_enabled',
              { resourceId, region, macieStatus: status ?? 'DISABLED' },
              {
                message: suspended
                  ? `Macie is currently in a SUSPENDED (paused) state in region ${region}`
                  : `Macie is not enabled in region ${region} while the account has S3 buckets with potentially sensitive data`,
              },
            ),
          );
        } else {
          logger.debug('Macie disabled but account has no S3 buckets; skipping macie_is_enabled (Prowler unused-service gate)');
        }
      }

      logger.info(`Macie scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Macie scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async accountHasS3Buckets(): Promise<boolean> {
    try {
      const result = await retry(async () => {
        return await this.client.s3.send(new ListBucketsCommand({}));
      });
      return (result.Buckets ?? []).length > 0;
    } catch (error) {
      // Presence unknown: treat as no buckets (matches Prowler, where a failed S3
      // enumeration leaves the region out of regions_with_buckets and the check is skipped).
      logger.debug('Macie: S3 ListBuckets probe failed; skipping macie_is_enabled gate', { error: (error as Error).message });
      return false;
    }
  }
}

export default MacieScanner;
