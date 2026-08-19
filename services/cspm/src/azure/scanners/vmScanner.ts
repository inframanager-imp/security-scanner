import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const MANAGEMENT_PORTS = ['22', '3389', '5985', '5986'];

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

      // ── VMs ───────────────────────────────────────────────────────────────
      const vms: any[] = [];
      for await (const vm of computeClient.virtualMachines.listAll()) vms.push(vm);

      for (const vm of vms) {
        const name = vm.name ?? 'unknown';
        const rg   = vm.id?.split('/')[4] ?? 'unknown';

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
              { message: `VM "${name}" has a public IP (${publicIps.join(', ')}) and NSG rules allow inbound port(s) ${exposedPorts.join(', ')} from 0.0.0.0/0. This exposes the VM to brute-force and exploitation attacks.` },
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
        }
      } catch { /* VMSS optional */ }

    } catch (err) {
      findings.push(this.finding(
        'Azure VM scan error',
        `Could not complete VM/VMSS scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Compute and Network resources.',
      ));
    }

    return findings;
  }
}
