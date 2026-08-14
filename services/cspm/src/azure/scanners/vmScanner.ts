// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const MANAGEMENT_PORTS = ['22', '3389', '5985', '5986'];

/** Approved VM SKU sizes for vm_desired_sku_size. Mirrors Prowler's configurable
 *  `desired_vm_sku_sizes` default when no organization-specific list is supplied. */
const DESIRED_SKU_SIZES = ['Standard_A8_v2', 'Standard_DS3_v2', 'Standard_D4s_v3'];

/** Minimum daily backup retention (days) for vm_sufficient_daily_backup_retention_period. */
const MIN_BACKUP_RETENTION_DAYS = 7;

function portMatches(spec: string, port: string): boolean {
  if (spec === '*' || spec === '0-65535') return true;
  if (spec.includes('-')) {
    const [lo, hi] = spec.split('-').map(Number);
    const p = Number(port);
    return !isNaN(lo) && !isNaN(hi) && p >= lo && p <= hi;
  }
  return spec === port;
}

function isEolImage(offer: string, sku: string): boolean {
  const o = offer.toLowerCase();
  const s = sku.toLowerCase();
  if (o.includes('windows-server') && (s.includes('2008') || s.includes('2012'))) return true;
  if ((o.includes('ubuntuserver') || o === 'ubuntu') && (s.startsWith('14.') || s.startsWith('16.') || s.startsWith('18.'))) return true;
  if (o.includes('centos') && (s.startsWith('6.') || s.startsWith('7.'))) return true;
  return false;
}

/** Extract {resourceGroup, name} from a VMSS resource ID for VM instance listing. */
function parseScaleSetId(id: string): { resourceGroup: string; name: string } | null {
  const parts = id.split('/');
  let resourceGroup = '';
  let name = '';
  for (let i = 0; i < parts.length; i++) {
    if (parts[i].toLowerCase() === 'resourcegroups' && i + 1 < parts.length) resourceGroup = parts[i + 1];
    if (parts[i].toLowerCase() === 'virtualmachinescalesets' && i + 1 < parts.length) name = parts[i + 1];
  }
  return resourceGroup && name ? { resourceGroup, name } : null;
}

export class AzureVMScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-VM');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const computeClient  = this.client.compute();
      const networkClient  = this.client.network();

      // ── Collect public IPs and their NIC associations ─────────────────────
      const publicIpByNicId = new Map<string, string>(); // nicId → publicIP address
      try {
        for await (const pip of networkClient.publicIPAddresses.listAll()) {
          const nicId = pip.ipConfiguration?.id?.split('/ipConfigurations/')[0]?.toLowerCase();
          if (nicId && pip.ipAddress) publicIpByNicId.set(nicId, pip.ipAddress);
        }
      } catch { /* best-effort */ }

      // ── Collect NSG rules indexed by NIC id ───────────────────────────────
      const nsgByNicId = new Map<string, any[]>(); // nicId → securityRules
      try {
        for await (const nic of networkClient.networkInterfaces.listAll()) {
          const nsgId = nic.networkSecurityGroup?.id;
          if (!nsgId || !nic.id) continue;
          const parts = nsgId.split('/');
          const nsgRg   = parts[4];
          const nsgName = parts[8];
          try {
            const nsg = await networkClient.networkSecurityGroups.get(nsgRg, nsgName);
            nsgByNicId.set(nic.id.toLowerCase(), nsg.securityRules ?? []);
          } catch { /* skip */ }
        }
      } catch { /* best-effort */ }

      // ── Disks (for CMK encryption checks) ─────────────────────────────────
      const disks: any[] = [];
      try {
        for await (const disk of computeClient.disks.list()) disks.push(disk);
      } catch { /* best-effort */ }

      // ── Backup coverage (Recovery Services vaults + protected items) ──────
      // vaultId -> { name, resourceGroup }; protected VM resourceId (lowercased) -> { vaultName, policyId }
      const backupByVmId = new Map<string, { vaultName: string; policyId?: string }>();
      // vaultResourceGroup/vaultName/policyName -> retention days
      const retentionByPolicyKey = new Map<string, number>();
      try {
        const recoveryClient = this.client.recoveryServices();
        const backupClient = this.client.recoveryServicesBackup();
        const vaults: any[] = [];
        for await (const vault of recoveryClient.vaults.listBySubscriptionId()) vaults.push(vault);

        for (const vault of vaults) {
          const vaultName = vault.name ?? '';
          const vaultRg = vault.id?.split('/')[4] ?? '';
          if (!vaultName || !vaultRg) continue;
          try {
            for await (const item of backupClient.backupProtectedItems.list(vaultName, vaultRg)) {
              const props: any = item.properties;
              if (!props || props.workloadType !== 'VM') continue;
              const sourceResourceId: string | undefined = props.sourceResourceId ?? props.virtualMachineId;
              if (!sourceResourceId) continue;
              backupByVmId.set(sourceResourceId.toLowerCase(), {
                vaultName,
                policyId: props.policyId,
              });
              // Resolve retention days for this policy, once per policy.
              if (props.policyId) {
                const policyName = props.policyId.split('/').pop();
                const key = `${vaultRg}/${vaultName}/${policyName}`;
                if (policyName && !retentionByPolicyKey.has(key)) {
                  try {
                    const policyResp: any = await backupClient.protectionPolicies.get(vaultName, vaultRg, policyName);
                    const retentionDuration = policyResp?.properties?.retentionPolicy?.dailySchedule?.retentionDuration;
                    if (retentionDuration?.count && retentionDuration?.durationType === 'Days') {
                      retentionByPolicyKey.set(key, retentionDuration.count);
                    }
                  } catch { /* skip — policy detail optional */ }
                }
              }
            }
          } catch { /* vault without backup items or insufficient permissions */ }
        }
      } catch { /* backup coverage optional — Recovery Services may not be provisioned */ }

      // ── JIT (Just-in-Time) access policies ─────────────────────────────────
      const jitEnabledVmIds = new Set<string>();
      try {
        const securityClient = this.client.securityCenter();
        const jitPolicies: any[] = [];
        try {
          for await (const p of securityClient.jitNetworkAccessPolicies.list()) jitPolicies.push(p);
        } catch {
          // Fallback: some subscriptions require resource-group scoped listing.
        }
        for (const policy of jitPolicies) {
          for (const vm of policy.virtualMachines ?? []) {
            if (vm.id) jitEnabledVmIds.add(String(vm.id).toLowerCase());
          }
        }
      } catch { /* JIT optional — requires Defender for Cloud */ }

      // ── VMs ───────────────────────────────────────────────────────────────
      const vms: any[] = [];
      for await (const vm of computeClient.virtualMachines.listAll()) vms.push(vm);

      for (const vm of vms) {
        const name = vm.name ?? 'unknown';
        const rg   = vm.id?.split('/')[4] ?? 'unknown';
        const vmIdLower = (vm.id ?? '').toLowerCase();

        // 1. OS disk encryption
        const osDisk           = vm.storageProfile?.osDisk;
        const diskEncryptionSet = osDisk?.managedDisk?.diskEncryptionSet?.id;
        const encryptionType    = osDisk?.managedDisk?.securityProfile?.securityEncryptionType;
        if (!diskEncryptionSet && !encryptionType) {
          const hasADEExtension = (vm.resources ?? []).some((r: any) =>
            r.name?.includes('AzureDiskEncryption'),
          );
          if (!hasADEExtension) {
            findings.push(this.emit(
              'vm_os_disk_encryption_not_enabled',
              { vm: name, resourceGroup: rg },
              { message: `VM "${name}" OS disk does not use Azure Disk Encryption (ADE) or a disk encryption set. Data at rest is unprotected against physical access.` },
            ));
          }
        }

        // 2. Public IP + management port exposure
        const nicIds = (vm.networkProfile?.networkInterfaces ?? [])
          .map((n: any) => (n.id ?? '').toLowerCase());

        const publicIps = nicIds.map((id: string) => publicIpByNicId.get(id)).filter(Boolean) as string[];
        if (publicIps.length > 0) {
          // Check if NSGs on those NICs allow management ports from internet
          const exposedPorts: string[] = [];
          for (const nicId of nicIds) {
            const rules = nsgByNicId.get(nicId) ?? [];
            for (const rule of rules) {
              if (rule.access !== 'Allow' || rule.direction !== 'Inbound') continue;
              const src = rule.sourceAddressPrefix ?? '';
              if (!['*', '0.0.0.0/0', 'Internet', 'Any'].includes(src)) continue;
              const portSpecs = [
                rule.destinationPortRange ?? '',
                ...(rule.destinationPortRanges ?? []),
              ].filter(Boolean);
              for (const port of MANAGEMENT_PORTS) {
                if (portSpecs.some(spec => portMatches(spec, port)) && !exposedPorts.includes(port)) {
                  exposedPorts.push(port);
                }
              }
            }
          }

          if (exposedPorts.length > 0) {
            findings.push(this.emit(
              'vm_public_ip_management_ports_exposed',
              { vm: name, publicIps, exposedPorts, resourceGroup: rg },
              {
                message: `VM "${name}" has a public IP (${publicIps.join(', ')}) and NSG rules allow inbound port(s) ${exposedPorts.join(', ')} from 0.0.0.0/0. This exposes the VM to brute-force and exploitation attacks.`,
              },
            ));
          } else {
            findings.push(this.emit(
              'vm_public_ip_address_assigned',
              { vm: name, publicIps, resourceGroup: rg },
              { message: `VM "${name}" has a directly-assigned public IP (${publicIps.join(', ')}). Public IPs increase attack surface even when NSG rules are currently restricted.` },
            ));
          }
        }

        // 3. Managed identity
        const identity = vm.identity;
        if (!identity || identity.type === 'None') {
          findings.push(this.emit(
            'vm_managed_identity_not_configured',
            { vm: name, resourceGroup: rg },
            { message: `VM "${name}" has no managed identity. Applications on this VM must use stored credentials to access Azure services, creating secret management risk.` },
          ));
        }

        // 4. EOL OS image
        const imageRef = vm.storageProfile?.imageReference;
        if (imageRef?.offer && imageRef?.sku) {
          if (isEolImage(imageRef.offer, imageRef.sku)) {
            findings.push(this.emit(
              'vm_eol_operating_system',
              { vm: name, offer: imageRef.offer, sku: imageRef.sku, resourceGroup: rg },
              { message: `VM "${name}" runs an EOL OS image (${imageRef.offer} / ${imageRef.sku}). EOL systems no longer receive security patches, leaving known CVEs unpatched.` },
            ));
          }
        }

        // 5. vm_desired_sku_size — Prowler: vm.vm_size in DESIRED_SKU_SIZES
        const vmSize = vm.hardwareProfile?.vmSize;
        if (vmSize && !DESIRED_SKU_SIZES.includes(vmSize)) {
          findings.push(this.emit(
            'vm_desired_sku_size',
            { vm: name, vmSize, resourceGroup: rg },
            { message: `VM "${name}" is using SKU size "${vmSize}", which is not on the organization-approved list (${DESIRED_SKU_SIZES.join(', ')}).` },
          ));
        }

        // 6. vm_ensure_using_approved_images — Prowler: image_reference is a
        // subscription-scoped /providers/Microsoft.Compute/images/<image> ID
        const imageRefId: string | undefined = vm.storageProfile?.imageReference?.id;
        const usesApprovedImage = !!imageRefId
          && imageRefId.startsWith('/subscriptions/')
          && imageRefId.includes('/providers/Microsoft.Compute/images/');
        if (!usesApprovedImage) {
          findings.push(this.emit(
            'vm_ensure_using_approved_images',
            { vm: name, imageReferenceId: imageRefId ?? null, resourceGroup: rg },
            { message: `VM "${name}" is not using an approved custom machine image (expected a /providers/Microsoft.Compute/images/<image> reference).` },
          ));
        }

        // 7. vm_ensure_using_managed_disks — OS disk and every data disk must
        // reference a managedDisk.
        const osDiskManaged = !!vm.storageProfile?.osDisk?.managedDisk;
        const dataDisks = vm.storageProfile?.dataDisks ?? [];
        const allDataDisksManaged = dataDisks.every((d: any) => !!d.managedDisk);
        if (!osDiskManaged || !allDataDisksManaged) {
          findings.push(this.emit(
            'vm_ensure_using_managed_disks',
            { vm: name, resourceGroup: rg },
            { message: `VM "${name}" is not using managed disks for all OS and data disks. Unmanaged (page-blob VHD) disks are being retired by Azure on 2026-03-31.` },
          ));
        }

        // 8. vm_jit_access_enabled
        if (!jitEnabledVmIds.has(vmIdLower)) {
          findings.push(this.emit(
            'vm_jit_access_enabled',
            { vm: name, resourceGroup: rg },
            { message: `VM "${name}" does not have Just-in-Time (JIT) access enabled. Management ports may be reachable without a time-bound, approved access request.` },
          ));
        }

        // 9. vm_linux_enforce_ssh_authentication — only applicable to Linux VMs
        const linuxConfig = vm.osProfile?.linuxConfiguration;
        if (linuxConfig) {
          if (!linuxConfig.disablePasswordAuthentication) {
            findings.push(this.emit(
              'vm_linux_enforce_ssh_authentication',
              { vm: name, resourceGroup: rg },
              { message: `Linux VM "${name}" has password authentication enabled (password-based SSH allowed). Enforce SSH key authentication instead.` },
            ));
          }
        }

        // 10. vm_trusted_launch_enabled
        const secProfile = vm.securityProfile;
        const trustedLaunchOk = !!secProfile
          && secProfile.securityType === 'TrustedLaunch'
          && secProfile.uefiSettings?.secureBootEnabled === true
          && secProfile.uefiSettings?.vTpmEnabled === true;
        if (!trustedLaunchOk) {
          findings.push(this.emit(
            'vm_trusted_launch_enabled',
            { vm: name, resourceGroup: rg },
            { message: `VM "${name}" has Trusted Launch disabled, or Secure Boot / vTPM are not both enabled. Boot-chain integrity protections are not fully active.` },
          ));
        }

        // 11 & 12. vm_backup_enabled / vm_sufficient_daily_backup_retention_period
        const backupEntry = backupByVmId.get(vmIdLower);
        if (!backupEntry) {
          findings.push(this.emit(
            'vm_backup_enabled',
            { vm: name, resourceGroup: rg },
            { message: `VM "${name}" is not protected by Azure Backup (not present in any Recovery Services vault).` },
          ));
        } else {
          findings.push(this.emit(
            'vm_backup_enabled',
            { vm: name, resourceGroup: rg, vault: backupEntry.vaultName },
            {
              message: `VM "${name}" is protected by Azure Backup (vault: ${backupEntry.vaultName}).`,
              severity: 'INFO',
            },
          ));

          const policyName = backupEntry.policyId?.split('/').pop();
          const vaultRgForVm = vm.id?.split('/')[4] ?? '';
          const retentionKey = policyName ? `${vaultRgForVm}/${backupEntry.vaultName}/${policyName}` : undefined;
          // Retention lookup is keyed by the vault's own resource group, not the VM's;
          // fall back to scanning known entries for this vault+policy if the direct key misses.
          let retentionDays: number | undefined = retentionKey ? retentionByPolicyKey.get(retentionKey) : undefined;
          if (retentionDays === undefined && policyName) {
            for (const [key, days] of retentionByPolicyKey.entries()) {
              if (key.endsWith(`/${backupEntry.vaultName}/${policyName}`)) {
                retentionDays = days;
                break;
              }
            }
          }

          if (retentionDays !== undefined) {
            if (retentionDays >= MIN_BACKUP_RETENTION_DAYS) {
              findings.push(this.emit(
                'vm_sufficient_daily_backup_retention_period',
                { vm: name, resourceGroup: rg, retentionDays },
                {
                  message: `VM "${name}" has a daily backup retention period of ${retentionDays} days (minimum required: ${MIN_BACKUP_RETENTION_DAYS}).`,
                  severity: 'INFO',
                },
              ));
            } else {
              findings.push(this.emit(
                'vm_sufficient_daily_backup_retention_period',
                { vm: name, resourceGroup: rg, retentionDays },
                { message: `VM "${name}" has insufficient daily backup retention period of ${retentionDays} days (minimum required: ${MIN_BACKUP_RETENTION_DAYS}).` },
              ));
            }
          }
        }
      }

      // ── Disks — vm_ensure_attached_disks_encrypted_with_cmk /
      // vm_ensure_unattached_disks_encrypted_with_cmk ─────────────────────────
      for (const disk of disks) {
        const diskName = disk.name ?? 'unknown';
        const diskRg = disk.id?.split('/')[4] ?? 'unknown';
        const vmsAttached: string[] = [
          ...(disk.managedBy ? [disk.managedBy] : []),
          ...(disk.managedByExtended ?? []),
        ];
        const encryptionType: string | undefined = disk.encryption?.type;
        const isCmk = !!encryptionType && encryptionType !== 'EncryptionAtRestWithPlatformKey';
        const checkId = vmsAttached.length > 0
          ? 'vm_ensure_attached_disks_encrypted_with_cmk'
          : 'vm_ensure_unattached_disks_encrypted_with_cmk';

        if (!isCmk) {
          findings.push(this.emit(
            checkId,
            { disk: diskName, resourceGroup: diskRg, attached: vmsAttached.length > 0 },
            { message: `Disk "${diskName}" is not encrypted with a customer-managed key (encryption type: ${encryptionType ?? 'default/platform-managed'}).` },
          ));
        }
      }

      // ── VMSS ─────────────────────────────────────────────────────────────
      try {
        const scaleSets: any[] = [];
        for await (const ss of computeClient.virtualMachineScaleSets.listAll()) scaleSets.push(ss);

        for (const ss of scaleSets) {
          const name = ss.name ?? 'unknown';
          const rg   = ss.id?.split('/')[4] ?? 'unknown';
          const profile = ss.virtualMachineProfile;

          // VMSS disk encryption
          const ssDiskEncSet = profile?.storageProfile?.osDisk?.managedDisk?.diskEncryptionSet?.id;
          if (!ssDiskEncSet) {
            findings.push(this.emit(
              'vmss_os_disk_encryption_not_enabled',
              { vmss: name, resourceGroup: rg },
              { message: `VMSS "${name}" does not have a disk encryption set configured on the OS disk. All scale-set instances run with unencrypted disks.` },
            ));
          }

          // VMSS EOL OS image
          const imageRef = profile?.storageProfile?.imageReference;
          if (imageRef?.offer && imageRef?.sku) {
            if (isEolImage(imageRef.offer, imageRef.sku)) {
              findings.push(this.emit(
                'vmss_eol_operating_system',
                { vmss: name, offer: imageRef.offer, sku: imageRef.sku, resourceGroup: rg },
                { message: `VMSS "${name}" uses EOL OS image (${imageRef.offer} / ${imageRef.sku}). All instances in the scale set are running an unsupported OS.` },
              ));
            }
          }

          // VMSS managed identity
          const identity = ss.identity;
          if (!identity || identity.type === 'None') {
            findings.push(this.emit(
              'vmss_managed_identity_not_configured',
              { vmss: name, resourceGroup: rg },
              { message: `VMSS "${name}" has no managed identity. Workloads running on scale-set instances must use stored credentials to access Azure services.` },
            ));
          }

          // VMSS overprovisioning (can expose brief extra instances)
          if (ss.overprovision === true) {
            findings.push(this.emit(
              'vmss_overprovisioning_enabled',
              { vmss: name, resourceGroup: rg },
              { message: `VMSS "${name}" has overprovisioning enabled. Azure temporarily creates more VMs than requested, which briefly exposes additional attack surface and may log data to disks that are discarded.` },
            ));
          }

          // vm_scaleset_associated_with_load_balancer
          const backendPools: string[] = [];
          const nicConfigs = profile?.networkProfile?.networkInterfaceConfigurations ?? [];
          for (const nic of nicConfigs) {
            for (const ipConf of nic.ipConfigurations ?? []) {
              for (const pool of ipConf.loadBalancerBackendAddressPools ?? []) {
                if (pool.id) backendPools.push(pool.id);
              }
            }
          }
          if (backendPools.length > 0) {
            findings.push(this.emit(
              'vm_scaleset_associated_with_load_balancer',
              { vmss: name, resourceGroup: rg, backendPools },
              {
                message: `Scale set "${name}" is associated with load balancer backend pool(s): ${backendPools.map(p => p.split('/').pop()).join(', ')}.`,
                severity: 'INFO',
              },
            ));
          } else {
            findings.push(this.emit(
              'vm_scaleset_associated_with_load_balancer',
              { vmss: name, resourceGroup: rg },
              { message: `Scale set "${name}" is not associated with any load balancer backend pool.` },
            ));
          }

          // vm_scaleset_not_empty
          let instanceCount = 0;
          const idParts = ss.id ? parseScaleSetId(ss.id) : null;
          if (idParts) {
            try {
              for await (const _inst of computeClient.virtualMachineScaleSetVMs.list(idParts.resourceGroup, idParts.name)) {
                instanceCount++;
              }
            } catch { /* instance listing optional */ }
          }
          if (instanceCount === 0) {
            findings.push(this.emit(
              'vm_scaleset_not_empty',
              { vmss: name, resourceGroup: rg },
              { message: `Scale set "${name}" is empty: no VM instances present.` },
            ));
          } else {
            findings.push(this.emit(
              'vm_scaleset_not_empty',
              { vmss: name, resourceGroup: rg, instanceCount },
              {
                message: `Scale set "${name}" has ${instanceCount} VM instance(s).`,
                severity: 'INFO',
              },
            ));
          }
        }
      } catch { /* VMSS optional */ }

    } catch (err) {
      findings.push(this.finding(
        'Azure VM scan error',
        `Could not complete VM/VMSS scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Compute, Network, Recovery Services, and Security Center (JIT) resources.',
      ));
    }

    return findings;
  }
}

export default AzureVMScanner;
