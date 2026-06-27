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
            findings.push(this.finding(
              'Virtual machine OS disk not encrypted',
              `VM "${name}" OS disk does not use Azure Disk Encryption (ADE) or a disk encryption set. Data at rest is unprotected against physical access.`,
              'HIGH',
              { vm: name, resourceGroup: rg },
              'Enable Azure Disk Encryption on VM disks or attach a disk encryption set backed by a customer-managed key in Key Vault.',
              ['vm', 'encryption'],
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
            findings.push(this.finding(
              'Virtual machine has public IP with management ports exposed',
              `VM "${name}" has a public IP (${publicIps.join(', ')}) and NSG rules allow inbound port(s) ${exposedPorts.join(', ')} from 0.0.0.0/0. This exposes the VM to brute-force and exploitation attacks.`,
              'CRITICAL',
              { vm: name, publicIps, exposedPorts, resourceGroup: rg },
              'Remove the public IP or restrict NSG inbound rules to specific trusted IPs. Use Azure Bastion for RDP/SSH instead of exposing management ports.',
              ['vm', 'public-ip', 'exposed-ports'],
            ));
          } else {
            findings.push(this.finding(
              'Virtual machine has a public IP address',
              `VM "${name}" has a directly-assigned public IP (${publicIps.join(', ')}). Public IPs increase attack surface even when NSG rules are currently restricted.`,
              'MEDIUM',
              { vm: name, publicIps, resourceGroup: rg },
              'Remove the public IP and access the VM via Azure Bastion, VPN, or ExpressRoute.',
              ['vm', 'public-ip'],
            ));
          }
        }

        // 3. Managed identity
        const identity = vm.identity;
        if (!identity || identity.type === 'None') {
          findings.push(this.finding(
            'Virtual machine does not use managed identity',
            `VM "${name}" has no managed identity. Applications on this VM must use stored credentials to access Azure services, creating secret management risk.`,
            'MEDIUM',
            { vm: name, resourceGroup: rg },
            'Assign a system-assigned or user-assigned managed identity so applications authenticate to Azure services without credentials.',
            ['vm', 'identity'],
          ));
        }

        // 4. EOL OS image
        const imageRef = vm.storageProfile?.imageReference;
        if (imageRef?.offer && imageRef?.sku) {
          if (isEolImage(imageRef.offer, imageRef.sku)) {
            findings.push(this.finding(
              'Virtual machine running end-of-life operating system',
              `VM "${name}" runs an EOL OS image (${imageRef.offer} / ${imageRef.sku}). EOL systems no longer receive security patches, leaving known CVEs unpatched.`,
              'HIGH',
              { vm: name, offer: imageRef.offer, sku: imageRef.sku, resourceGroup: rg },
              'Migrate to a supported OS. For Windows 2008/2012 use Windows Server 2022. For Ubuntu 14/16/18 use Ubuntu 22.04 LTS or 24.04 LTS.',
              ['vm', 'eol-os'],
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
            findings.push(this.finding(
              'Virtual Machine Scale Set OS disk not encrypted',
              `VMSS "${name}" does not have a disk encryption set configured on the OS disk. All scale-set instances run with unencrypted disks.`,
              'HIGH',
              { vmss: name, resourceGroup: rg },
              'Configure a disk encryption set with a customer-managed key on the VMSS OS disk profile.',
              ['vmss', 'encryption'],
            ));
          }

          // VMSS EOL OS image
          const imageRef = profile?.storageProfile?.imageReference;
          if (imageRef?.offer && imageRef?.sku) {
            if (isEolImage(imageRef.offer, imageRef.sku)) {
              findings.push(this.finding(
                'Virtual Machine Scale Set running end-of-life operating system',
                `VMSS "${name}" uses EOL OS image (${imageRef.offer} / ${imageRef.sku}). All instances in the scale set are running an unsupported OS.`,
                'HIGH',
                { vmss: name, offer: imageRef.offer, sku: imageRef.sku, resourceGroup: rg },
                'Update the VMSS image reference to a supported OS version and re-image all instances.',
                ['vmss', 'eol-os'],
              ));
            }
          }

          // VMSS managed identity
          const identity = ss.identity;
          if (!identity || identity.type === 'None') {
            findings.push(this.finding(
              'Virtual Machine Scale Set does not use managed identity',
              `VMSS "${name}" has no managed identity. Workloads running on scale-set instances must use stored credentials to access Azure services.`,
              'MEDIUM',
              { vmss: name, resourceGroup: rg },
              'Assign a managed identity to the VMSS so all instances can authenticate to Azure services without credentials.',
              ['vmss', 'identity'],
            ));
          }

          // VMSS overprovisioning (can expose brief extra instances)
          if (ss.overprovision === true) {
            findings.push(this.finding(
              'Virtual Machine Scale Set overprovisioning enabled',
              `VMSS "${name}" has overprovisioning enabled. Azure temporarily creates more VMs than requested, which briefly exposes additional attack surface and may log data to disks that are discarded.`,
              'LOW',
              { vmss: name, resourceGroup: rg },
              'Disable overprovisioning if workload data sensitivity requires it, or ensure ephemeral disks are used so discarded instances leave no data.',
              ['vmss', 'configuration'],
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
