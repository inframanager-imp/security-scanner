// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  BackupClient,
  ListBackupVaultsCommand,
  ListBackupPlansCommand,
  ListReportPlansCommand,
  ListRecoveryPointsByBackupVaultCommand,
} from '@aws-sdk/client-backup';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Cap recovery-point evaluation per vault (mirrors Prowler's
// max_backup_recovery_points resource limit) to bound API cost.
const MAX_RECOVERY_POINTS_PER_VAULT = 100;

export class BackupScanner extends BaseScanner {
  private backup: BackupClient;

  constructor(client: AWSClient) {
    super(client, 'Backup');
    this.backup = new BackupClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Backup security scan...');

      const vaults = await this.listBackupVaults();
      const plans = await this.listBackupPlans();

      // backup_vaults_exist: fail when no vault exists at all
      if (vaults.length === 0) {
        findings.push(this.emit(
          'backup_vaults_exist',
          { vaultCount: 0 },
          { message: 'No AWS Backup vault exists in this region, so no centrally managed recovery points can be stored' }
        ));
      }

      // backup_plans_exist: Prowler only fails when vaults exist but no plan does
      if (vaults.length > 0 && plans.length === 0) {
        findings.push(this.emit(
          'backup_plans_exist',
          { vaultCount: vaults.length, planCount: 0 },
          { message: 'Backup vaults exist but no AWS Backup plan is configured in this region, so resources are not being backed up on a schedule' }
        ));
      }

      // backup_reportplans_exist: only evaluated when backup plans exist
      if (plans.length > 0) {
        try {
          const reportPlans = await this.listReportPlans();
          if (reportPlans.length === 0) {
            findings.push(this.emit(
              'backup_reportplans_exist',
              { planCount: plans.length, reportPlanCount: 0 },
              { message: 'Backup plans exist but no AWS Backup report plan is configured, so backup job and compliance activity is not being reported' }
            ));
          }
        } catch (error) {
          logger.debug('Failed to list Backup report plans', { error: (error as Error).message });
        }
      }

      for (const vault of vaults) {
        const vaultName = vault.BackupVaultName || 'Unknown';
        logger.debug(`Scanning backup vault: ${vaultName}`);

        // backup_vaults_encrypted
        if (!vault.EncryptionKeyArn) {
          findings.push(this.emit(
            'backup_vaults_encrypted',
            { vault: vaultName, vaultArn: vault.BackupVaultArn },
            { message: `Backup vault "${vaultName}" is not encrypted at rest with a KMS key` }
          ));
        }

        // backup_recovery_point_encrypted
        const rpFindings = await this.checkRecoveryPoints(vaultName);
        findings.push(...rpFindings);
      }

      logger.info(`Backup scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Backup scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listBackupVaults(): Promise<any[]> {
    return retry(async () => {
      logger.debug('Fetching backup vaults...');
      const vaults: any[] = [];
      let nextToken: string | undefined;
      do {
        const result: any = await this.backup.send(
          new ListBackupVaultsCommand({ NextToken: nextToken })
        );
        vaults.push(...(result.BackupVaultList || []));
        nextToken = result.NextToken;
      } while (nextToken);
      return vaults;
    });
  }

  private async listBackupPlans(): Promise<any[]> {
    return retry(async () => {
      logger.debug('Fetching backup plans...');
      const plans: any[] = [];
      let nextToken: string | undefined;
      do {
        const result: any = await this.backup.send(
          new ListBackupPlansCommand({ NextToken: nextToken })
        );
        plans.push(...(result.BackupPlansList || []));
        nextToken = result.NextToken;
      } while (nextToken);
      return plans;
    });
  }

  private async listReportPlans(): Promise<any[]> {
    return retry(async () => {
      logger.debug('Fetching backup report plans...');
      const result: any = await this.backup.send(new ListReportPlansCommand({}));
      return result.ReportPlans || [];
    });
  }

  private async checkRecoveryPoints(vaultName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result: any = await retry(async () => {
        return await this.backup.send(
          new ListRecoveryPointsByBackupVaultCommand({
            BackupVaultName: vaultName,
            MaxResults: MAX_RECOVERY_POINTS_PER_VAULT,
          })
        );
      });

      for (const recoveryPoint of result.RecoveryPoints || []) {
        if (!recoveryPoint.IsEncrypted) {
          const rpArn = recoveryPoint.RecoveryPointArn || 'Unknown';
          const rpId = rpArn.split(':').pop();
          findings.push(this.emit(
            'backup_recovery_point_encrypted',
            { vault: vaultName, recoveryPointArn: rpArn, isEncrypted: false },
            { message: `Recovery point "${rpId}" in backup vault "${vaultName}" is not encrypted at rest` }
          ));
        }
      }
    } catch (error) {
      logger.debug(`Failed to list recovery points for vault ${vaultName}`, { error: (error as Error).message });
    }

    return findings;
  }
}

export default BackupScanner;
