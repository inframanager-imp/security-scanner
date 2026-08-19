import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const SENSITIVE_PORTS = [22, 3389, 5432, 3306, 1433, 6379, 27017, 9200, 8080, 8443];

export class GcpComputeScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-Compute');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      await Promise.all([
        this.checkInstances(project, findings),
        this.checkFirewallRules(project, findings),
        this.checkVPCNetworks(project, findings),
      ]);
    } catch (err) {
      findings.push(this.finding(
        'GCP Compute scan error',
        `Could not complete Compute Engine scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service account has roles/compute.viewer on the project.',
      ));
    }

    return findings;
  }

  private async checkInstances(project: string, findings: ScanningResult[]): Promise<void> {
    try {
      const compute = this.client.compute();
      const res = await compute.instances.aggregatedList({
        project,
        maxResults: 500,
      });
      const aggregated = res.data.items ?? {};

      const instances: any[] = [];
      for (const zone of Object.values(aggregated)) {
        instances.push(...((zone as any).instances ?? []));
      }

      for (const instance of instances) {
        const name = instance.name ?? 'unknown';
        const zone = instance.zone?.split('/').pop() ?? 'unknown';

        // 1. Public IP address
        const hasPublicIP = (instance.networkInterfaces ?? []).some((iface: any) =>
          (iface.accessConfigs ?? []).some((ac: any) => ac.natIP),
        );
        if (hasPublicIP) {
          const publicIPs = (instance.networkInterfaces ?? [])
            .flatMap((i: any) => (i.accessConfigs ?? []))
            .filter((ac: any) => ac.natIP)
            .map((ac: any) => ac.natIP);
          findings.push(this.emit(
            'compute_instance_public_ip_address',
            { instance: name, zone, project, publicIPs },
            { message: `VM instance "${name}" (zone: ${zone}) has a public IP: ${publicIPs.join(', ')}. Public IPs expose the instance directly to internet-based attacks.` },
          ));
        }

        // 2. OS Login disabled (SSH key-based auth)
        const osLoginEnabled = (instance.metadata?.items ?? []).some((item: any) =>
          item.key === 'enable-oslogin' && item.value?.toLowerCase() === 'true',
        );
        if (!osLoginEnabled) {
          findings.push(this.emit(
            'compute_instance_metadata_os_login_enabled',
            { instance: name, zone, project },
            { message: `VM instance "${name}" (zone: ${zone}) does not have OS Login enabled. Without OS Login, SSH access is managed via project/instance metadata SSH keys, which bypass IAM-based access controls and MFA.` },
          ));
        }

        // 3. Serial port enabled
        const serialEnabled = (instance.metadata?.items ?? []).some((item: any) =>
          item.key === 'serial-port-enable' && (item.value === '1' || item.value?.toLowerCase() === 'true'),
        );
        if (serialEnabled) {
          findings.push(this.emit(
            'compute_instance_serial_port_metadata_disabled',
            { instance: name, zone, project },
            { message: `VM instance "${name}" (zone: ${zone}) has serial port (console) access enabled. Serial port access allows interactive debugging sessions that bypass normal authentication, potentially exposing credentials in the console output.` },
          ));
        }

        // 4. Disk encryption (CMEK)
        const disks = instance.disks ?? [];
        const unencryptedDisks = disks.filter((d: any) => !d.diskEncryptionKey?.kmsKeyName);
        if (unencryptedDisks.length > 0 && disks.length > 0) {
          findings.push(this.emit(
            'compute_instance_disks_cmek_encrypted',
            { instance: name, zone, project, unencryptedDiskCount: unencryptedDisks.length },
            { message: `VM instance "${name}" (zone: ${zone}) has ${unencryptedDisks.length} disk(s) using Google-managed encryption. CMEK gives control over key lifecycle and enables key revocation.` },
          ));
        }

        // 5. No service account / default service account
        const saEmail = instance.serviceAccounts?.[0]?.email;
        if (!saEmail) {
          findings.push(this.emit(
            'compute_instance_service_account_configured',
            { instance: name, zone, project },
            { message: `VM instance "${name}" (zone: ${zone}) has no service account. Workloads running on this instance cannot authenticate to GCP APIs using ADC (Application Default Credentials).` },
          ));
        } else if (saEmail.endsWith('-compute@developer.gserviceaccount.com')) {
          findings.push(this.emit(
            'compute_instance_default_service_account_in_use',
            { instance: name, zone, project, serviceAccount: saEmail },
            { message: `VM instance "${name}" (zone: ${zone}) uses the default Compute Engine service account "${saEmail}" which typically has the Editor role, granting broad write access to all GCP APIs.` },
          ));
        }

        // 6. Shielded VM not enabled
        const shieldedConfig = instance.shieldedInstanceConfig;
        if (!shieldedConfig?.enableSecureBoot || !shieldedConfig?.enableVtpm) {
          findings.push(this.emit(
            'compute_instance_shielded_secure_boot_vtpm_enabled',
            { instance: name, zone, project, secureBoot: shieldedConfig?.enableSecureBoot, vtpm: shieldedConfig?.enableVtpm },
            { message: `VM instance "${name}" (zone: ${zone}) does not have Shielded VM features (Secure Boot, vTPM) enabled. Shielded VMs protect against rootkits, bootkits, and kernel-level malware.` },
          ));
        }
      }
    } catch { /* optional */ }
  }

  private async checkFirewallRules(project: string, findings: ScanningResult[]): Promise<void> {
    try {
      const compute = this.client.compute();
      const res     = await compute.firewalls.list({ project });
      const rules   = res.data.items ?? [];

      for (const rule of rules) {
        if (rule.direction !== 'INGRESS') continue;
        const name = rule.name ?? 'unknown';

        const sourceRanges = rule.sourceRanges ?? [];
        const isOpen       = sourceRanges.includes('0.0.0.0/0') || sourceRanges.includes('::/0');
        if (!isOpen) continue;

        // Check for any allowed ports
        for (const allowed of rule.allowed ?? []) {
          const protocol = allowed.IPProtocol ?? '';
          const ports    = allowed.ports ?? [];

          // All traffic (no port restriction)
          if (ports.length === 0 && (protocol === 'tcp' || protocol === 'udp' || protocol === 'all')) {
            findings.push(this.emit(
              'compute_firewall_open_ingress_from_internet',
              { rule: name, project, protocol, sourceRanges, direction: 'INGRESS' },
              { message: `Firewall rule "${name}" in project "${project}" allows all ${protocol.toUpperCase()} traffic from any source. This exposes all instances matching the target to internet-based attacks.` },
            ));
            continue;
          }

          for (const port of ports) {
            const portNum = parseInt(port.split('-')[0], 10);
            if (isNaN(portNum)) continue;

            if (portNum === 22) {
              findings.push(this.emit(
                'compute_firewall_ssh_exposed_generic',
                { rule: name, project, port: '22', protocol: 'tcp' },
                { message: `Firewall rule "${name}" allows SSH access (TCP/22) from 0.0.0.0/0. Any internet-connected host can attempt to connect to instances matching this rule.` },
              ));
            } else if (portNum === 3389) {
              findings.push(this.emit(
                'compute_firewall_rdp_exposed_generic',
                { rule: name, project, port: '3389', protocol: 'tcp' },
                { message: `Firewall rule "${name}" allows RDP access (TCP/3389) from 0.0.0.0/0. Windows RDP exposed to the internet is a primary target for brute-force and ransomware attacks.` },
              ));
            } else if (SENSITIVE_PORTS.includes(portNum)) {
              findings.push(this.emit(
                'compute_firewall_sensitive_port_exposed',
                { rule: name, project, port: String(portNum), protocol },
                { message: `Firewall rule "${name}" allows inbound ${protocol.toUpperCase()} port ${portNum} from 0.0.0.0/0. Sensitive services exposed to the internet are at risk of exploitation.` },
              ));
            }
          }
        }
      }

      // Check for default-allow-* rules that are still enabled
      const defaultRules = rules.filter(r =>
        (r.name?.startsWith('default-allow-ssh') || r.name?.startsWith('default-allow-rdp') || r.name?.startsWith('default-allow-icmp')) &&
        !r.disabled,
      );
      for (const r of defaultRules) {
        findings.push(this.emit(
          'compute_firewall_default_rule_enabled',
          { rule: r.name, project, direction: r.direction, sourceRanges: r.sourceRanges },
          { message: `The default firewall rule "${r.name}" in project "${project}" is enabled and allows access from 0.0.0.0/0. Default rules are broad and should be replaced with more restrictive custom rules.` },
        ));
      }
    } catch { /* optional */ }
  }

  private async checkVPCNetworks(project: string, findings: ScanningResult[]): Promise<void> {
    try {
      const compute = this.client.compute();
      const res     = await compute.networks.list({ project });
      const networks = res.data.items ?? [];

      // Check if default VPC is used
      const defaultVPC = networks.find(n => n.name === 'default');
      if (defaultVPC) {
        findings.push(this.emit(
          'compute_network_default_in_use',
          { project, networkName: 'default', subnetMode: defaultVPC.autoCreateSubnetworks ? 'auto' : 'custom' },
          { message: `The project "${project}" still uses the default VPC network. The default VPC is automatically created with permissive pre-populated firewall rules (allow SSH, RDP, ICMP from 0.0.0.0/0) and does not follow network segmentation best practices.` },
        ));
      }

      // Check for auto-mode VPCs (creates subnets in all regions automatically)
      const autoNetworks = networks.filter(n => n.autoCreateSubnetworks && n.name !== 'default');
      for (const net of autoNetworks) {
        findings.push(this.emit(
          'compute_network_auto_mode_subnet_creation',
          { project, network: net.name },
          { message: `VPC network "${net.name}" in project "${project}" uses auto-mode which automatically creates subnets in all GCP regions. This results in unnecessarily broad network footprint and may create subnets in unintended regions.` },
        ));
      }

      // Check for VPCs with no subnets (orphaned)
      for (const net of networks) {
        if (net.subnetworks?.length === 0 && net.name !== 'default') {
          findings.push(this.emit(
            'compute_network_empty_vpc',
            { project, network: net.name },
            { message: `VPC network "${net.name}" in project "${project}" has no subnets. Empty VPCs represent unused network resources.` },
          ));
        }
      }
    } catch { /* optional */ }
  }
}
