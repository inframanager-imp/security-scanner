// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  GlacierClient,
  ListVaultsCommand,
  GetVaultAccessPolicyCommand,
} from '@aws-sdk/client-glacier';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class GlacierScanner extends BaseScanner {
  private glacier: GlacierClient;

  constructor(client: AWSClient) {
    super(client, 'Glacier');
    this.glacier = new GlacierClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Glacier security scan...');

      const vaults = await this.listVaults();
      for (const vault of vaults) {
        const vaultName: string = vault.VaultName ?? '';
        if (!vaultName) continue;
        logger.debug(`Scanning Glacier vault: ${vaultName}`);
        try {
          const vaultFindings = await this.validateVault(vaultName, vault.VaultARN ?? '');
          findings.push(...vaultFindings);
        } catch (error) {
          logger.debug(`Failed to scan Glacier vault ${vaultName}`, { error: (error as Error).message });
        }
      }

      logger.info(`Glacier scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Glacier scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listVaults(): Promise<any[]> {
    const vaults: any[] = [];
    let marker: string | undefined;
    do {
      const result = await retry(async () => {
        // accountId '-' means the account that owns the credentials
        return await this.glacier.send(new ListVaultsCommand({ accountId: '-', marker }));
      });
      vaults.push(...(result.VaultList ?? []));
      marker = result.Marker;
    } while (marker);
    return vaults;
  }

  private async validateVault(vaultName: string, vaultArn: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    let accessPolicy: any = null;
    try {
      const result = await retry(async () => {
        return await this.glacier.send(new GetVaultAccessPolicyCommand({ accountId: '-', vaultName }));
      });
      if (result.policy?.Policy) {
        accessPolicy = JSON.parse(result.policy.Policy);
      }
    } catch (error) {
      if ((error as Error).name === 'ResourceNotFoundException') {
        // Vault has no access policy => not public
        accessPolicy = null;
      } else {
        throw error;
      }
    }

    // glacier_vaults_policy_public_access: Allow statements must not grant access to everyone
    if (accessPolicy) {
      const statements: any[] = Array.isArray(accessPolicy.Statement)
        ? accessPolicy.Statement
        : (accessPolicy.Statement ? [accessPolicy.Statement] : []);

      let publicAccess = false;
      for (const statement of statements) {
        if (statement?.Effect !== 'Allow') continue;
        const principal = statement.Principal;
        if (
          this.principalValueIsPublic(principal) ||
          (principal && typeof principal === 'object' && this.principalValueIsPublic(principal.AWS)) ||
          (principal && typeof principal === 'object' && this.principalValueIsPublic(principal.CanonicalUser))
        ) {
          publicAccess = true;
          break;
        }
      }

      if (publicAccess) {
        findings.push(this.emit(
          'glacier_vaults_policy_public_access',
          { vaultName, vaultArn, policy: accessPolicy },
          {
            message: `Vault ${vaultName} has policy which allows access to everyone`,
            remediation: `Restrict the access policy of vault "${vaultName}" to specific AWS principals, or remove the public policy (aws glacier delete-vault-access-policy --account-id <account-id> --vault-name ${vaultName})`,
          }
        ));
      }
    }

    return findings;
  }

  private principalValueIsPublic(value: any): boolean {
    if (typeof value === 'string') return value.includes('*');
    if (Array.isArray(value)) return value.some((v) => typeof v === 'string' && v.includes('*'));
    return false;
  }
}

export default GlacierScanner;
