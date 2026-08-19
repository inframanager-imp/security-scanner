import {
  ListKeysCommand,
  DescribeKeyCommand,
  GetKeyRotationStatusCommand
} from '@aws-sdk/client-kms';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class KMSScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'KMS');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting KMS security scan...');

      const keys = await this.listKeys();
      for (const keyId of keys) {
        logger.debug(`Scanning KMS key: ${keyId}`);

        const keyFindings = await this.validateKey(keyId);
        findings.push(...keyFindings);
      }

      logger.info(`KMS scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('KMS scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listKeys(): Promise<string[]> {
    return retry(async () => {
      logger.debug('Fetching KMS keys...');
      const keys: string[] = [];
      let marker: string | undefined;

      do {
        const result = await this.client.kms.send(
          new ListKeysCommand({ Marker: marker, Limit: 1000 })
        );
        keys.push(...(result.Keys?.map(k => k.KeyId || '') || []));
        marker = result.NextMarker;
      } while (marker);

      return keys;
    });
  }

  private async validateKey(keyId: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const details = await retry(async () => {
        const cmd = new DescribeKeyCommand({ KeyId: keyId });
        return await this.client.kms.send(cmd);
      });

      if (!details.KeyMetadata) return findings;

      const metadata = details.KeyMetadata;

      // Check if key is pending deletion
      if (metadata.KeyState === 'PendingDeletion') {
        findings.push(this.emit(
          'kms_cmk_not_deleted_unintentionally',
          { keyId, state: metadata.KeyState },
          {
            message: `KMS key ${keyId} is pending deletion`,
          }
        ));
      }

      // Check if key is disabled
      if (metadata.KeyState === 'Disabled') {
        findings.push(this.emit(
          'kms_cmk_are_used',
          { keyId, state: metadata.KeyState },
          {
            message: `KMS key ${keyId} is disabled`,
            remediation: `Enable KMS key ${keyId} if it's still needed`,
          }
        ));
      }

      // Check rotation for customer-managed keys
      if (metadata.KeyManager === 'CUSTOMER') {
        try {
          const rotationStatus = await repeat(async () => {
            const cmd = new GetKeyRotationStatusCommand({ KeyId: keyId });
            return await this.client.kms.send(cmd);
          });

          if (!rotationStatus.KeyRotationEnabled) {
            findings.push(this.emit(
              'kms_cmk_rotation_enabled',
              { keyId, rotationEnabled: rotationStatus.KeyRotationEnabled },
              {
                message: `Customer-managed KMS key ${keyId} does not have automatic rotation enabled`,
                remediation: `Enable automatic key rotation for customer-managed KMS key ${keyId}`,
              }
            ));
          }
        } catch (error) {
          logger.debug(`Failed to check rotation for key ${keyId}`, { error: (error as Error).message });
        }
      }
    } catch (error) {
      logger.debug(`Failed to validate KMS key ${keyId}`, { error: (error as Error).message });
    }

    return findings;
  }
}

// Helper function
async function repeat<T>(fn: () => Promise<T>, maxRetries: number = 3, delayMs: number = 1000): Promise<T> {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, delayMs * Math.pow(2, i)));
    }
  }
  throw new Error('Retry failed');
}

export default KMSScanner;
