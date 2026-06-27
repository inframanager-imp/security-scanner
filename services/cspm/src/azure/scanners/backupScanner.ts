import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureBackupScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-Backup');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const recoveryClient = this.client.recoveryServices();

      const vaults: any[] = [];
      for await (const v of recoveryClient.vaults.listBySubscriptionId()) vaults.push(v);

      if (vaults.length === 0) return findings;

      for (const vault of vaults) {
        const name = vault.name ?? 'unknown';
        const rg   = vault.id?.split('/')[4] ?? 'unknown';

        // 1. Soft delete disabled
        const softDelete = vault.properties?.securitySettings?.softDeleteSettings?.softDeleteState ?? 'Enabled';
        if (softDelete !== 'Enabled' && softDelete !== 'AlwaysON') {
          findings.push(this.finding(
            'Azure Backup vault has soft delete disabled',
            `Recovery Services vault "${name}" has soft delete disabled or set to "${softDelete}". Without soft delete, backup data deleted by ransomware or a compromised admin is immediately and permanently lost.`,
            'CRITICAL',
            { vault: name, resourceGroup: rg, softDeleteState: softDelete },
            'Enable soft delete on the Recovery Services vault and set the retention period to at least 14 days. Consider using "AlwaysON" (irreversible) for critical production vaults.',
            ['backup', 'soft-delete', 'ransomware'],
          ));
        }

        // 2. Multi-user authorization (MUA) not enabled
        const mua = (vault.properties as any)?.resourceGuardOperationRequests;
        const hasMUA = Array.isArray(mua) && mua.length > 0;
        if (!hasMUA) {
          findings.push(this.finding(
            'Azure Backup vault does not have Multi-User Authorization (MUA) enabled',
            `Recovery Services vault "${name}" has no Resource Guard (MUA) configured. A single compromised privileged account can disable soft delete, modify backup policies, or delete backup data without secondary approval.`,
            'HIGH',
            { vault: name, resourceGroup: rg },
            'Configure Multi-User Authorization by associating a Resource Guard (in a different subscription or tenant) with the vault. This requires approval from the Resource Guard owner for destructive operations.',
            ['backup', 'mua', 'authorization'],
          ));
        }

        // 3. Immutability not enabled
        const immutability = (vault.properties as any)?.immutabilitySettings?.state ?? 'Disabled';
        if (immutability === 'Disabled') {
          findings.push(this.finding(
            'Azure Backup vault does not have immutability enabled',
            `Recovery Services vault "${name}" has immutability disabled. Backup data can be modified or deleted before the retention period expires, enabling ransomware actors to destroy backups.`,
            'HIGH',
            { vault: name, resourceGroup: rg, immutabilityState: immutability },
            'Enable vault immutability (Locked mode for maximum protection). Immutable vaults prevent deletion or modification of backup data before the retention period.',
            ['backup', 'immutability', 'ransomware'],
          ));
        }

        // 4. Cross-region restore not enabled (for HA)
        const crrEnabled = (vault.properties as any)?.crossRegionRestore === 'Enabled';
        if (!crrEnabled) {
          findings.push(this.finding(
            'Azure Backup vault has Cross Region Restore (CRR) disabled',
            `Recovery Services vault "${name}" has Cross Region Restore disabled. If the primary Azure region experiences a disaster, backups cannot be restored in a secondary region.`,
            'MEDIUM',
            { vault: name, resourceGroup: rg },
            'Enable Cross Region Restore on the Recovery Services vault to allow restoring backups in the paired Azure region during a primary region outage.',
            ['backup', 'disaster-recovery'],
          ));
        }

        // 5. Encryption using CMK
        const encryptionType = vault.properties?.encryption?.kekIdentity?.userAssignedIdentity ??
          (vault.properties as any)?.encryption?.keyUri;
        if (!encryptionType) {
          findings.push(this.finding(
            'Azure Backup vault does not use a customer-managed key for encryption',
            `Recovery Services vault "${name}" encrypts backup data using Microsoft-managed keys (platform keys). Customer-managed keys give full control over key lifecycle and revocation of access to backup data.`,
            'MEDIUM',
            { vault: name, resourceGroup: rg },
            'Configure a customer-managed key from Azure Key Vault for vault encryption. Assign a managed identity to the vault for Key Vault access.',
            ['backup', 'encryption', 'cmk'],
          ));
        }

        // 6. Public network access
        const publicAccess = (vault.properties as any)?.publicNetworkAccess ?? 'Enabled';
        if (publicAccess === 'Enabled') {
          findings.push(this.finding(
            'Azure Backup vault has public network access enabled',
            `Recovery Services vault "${name}" is accessible from the public internet. Backup management API is exposed, which could allow unauthorized policy modifications or data access with compromised credentials.`,
            'MEDIUM',
            { vault: name, resourceGroup: rg },
            'Disable public network access on the vault and configure Private Endpoints for backup traffic.',
            ['backup', 'network', 'public-access'],
          ));
        }

        // 7. Diagnostic logs
        try {
          const monitorClient = this.client.monitor();
          const settingsResult = await monitorClient.diagnosticSettings.list(vault.id!);
          const settings: any[] = settingsResult.value ?? [];
          const hasLogs = settings.some(s =>
            s.logs?.some((l: any) => l.enabled) || s.metrics?.some((m: any) => m.enabled),
          );
          if (!hasLogs) {
            findings.push(this.finding(
              'Azure Backup vault has no diagnostic logs configured',
              `Recovery Services vault "${name}" has no diagnostic settings. Without logs, backup job failures, policy changes, and unauthorized operations cannot be detected or investigated.`,
              'MEDIUM',
              { vault: name, resourceGroup: rg },
              'Enable diagnostic settings to capture AzureBackupReport logs and send to a Log Analytics workspace. Create alerts for backup job failures and policy modification events.',
              ['backup', 'logging'],
            ));
          }
        } catch { /* optional */ }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Backup scan error',
        `Could not complete Recovery Services vault scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Recovery Services vaults.',
      ));
    }

    return findings;
  }
}
