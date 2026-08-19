import {
  ListSecretsCommand,
  DescribeSecretCommand
} from '@aws-sdk/client-secrets-manager';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class SecretsManagerScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'SecretsManager');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Secrets Manager security scan...');

      const secrets = await this.listSecrets();
      for (const secret of secrets) {
        const secretName = secret.Name || 'Unknown';
        logger.debug(`Scanning secret: ${secretName}`);

        const secretFindings = await this.validateSecret(secret);
        findings.push(...secretFindings);
      }

      logger.info(`Secrets Manager scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Secrets Manager scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listSecrets(): Promise<any[]> {
    return retry(async () => {
      logger.debug('Fetching secrets...');
      const secrets: any[] = [];
      let token: string | undefined;

      do {
        const result = await this.client.secretsmanager.send(
          new ListSecretsCommand({ NextToken: token, MaxResults: 100 })
        );
        secrets.push(...(result.SecretList || []));
        token = result.NextToken;
      } while (token);

      return secrets;
    });
  }

  private async validateSecret(secret: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const secretName = secret.Name || 'Unknown';

    try {
      const details = await retry(async () => {
        const cmd = new DescribeSecretCommand({ SecretId: secretName });
        return await this.client.secretsmanager.send(cmd);
      });

      // Check if secret is scheduled for deletion
      if (details.DeletedDate) {
        findings.push(this.emit(
          'secretsmanager_secret_scheduled_for_deletion',
          { secretName, deleteDate: details.DeletedDate },
          {
            message: `Secret "${secretName}" is scheduled for deletion`,
          }
        ));
      }

      // Check rotation
      if (!details.RotationEnabled) {
        findings.push(this.emit(
          'secretsmanager_automatic_rotation_enabled',
          { secretName, rotationEnabled: details.RotationEnabled },
          {
            message: `Secret "${secretName}" does not have rotation enabled`,
            remediation: `Enable automatic rotation for secret "${secretName}"`,
          }
        ));
      }

      // Check encryption
      if (!details.KmsKeyId) {
        findings.push(this.emit(
          'secretsmanager_secret_encrypted_with_cmk',
          { secretName, kmsKey: details.KmsKeyId },
          {
            message: `Secret "${secretName}" uses default encryption instead of KMS`,
            remediation: `Consider using a customer-managed KMS key for secret "${secretName}"`,
          }
        ));
      }

      // Check replication
      if (!details.ReplicationStatus || details.ReplicationStatus.length === 0) {
        findings.push(this.emit(
          'secretsmanager_secret_cross_region_replication',
          { secretName, replicated: details.ReplicationStatus?.length === 0 },
          {
            message: `Secret "${secretName}" is not replicated for disaster recovery`,
            remediation: `Replicate secret "${secretName}" to another region for disaster recovery`,
          }
        ));
      }

      // Check for access logs/auditing
      // This typically requires additional configuration that we can flag as a recommendation
    } catch (error) {
      logger.debug(`Failed to validate secret ${secretName}`, { error: (error as Error).message });
    }

    return findings;
  }
}

export default SecretsManagerScanner;
