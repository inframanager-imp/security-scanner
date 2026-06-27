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
          findings.push(this.finding(
            'Compute Engine instance has a public IP address',
            `VM instance "${name}" (zone: ${zone}) has a public IP: ${publicIPs.join(', ')}. Public IPs expose the instance directly to internet-based attacks.`,
            'HIGH',
            { instance: name, zone, project, publicIPs },
            'Remove public IPs from Compute instances that do not need direct internet connectivity. Use Cloud NAT for outbound traffic and a load balancer or Identity-Aware Proxy for inbound access.',
            ['compute', 'network', 'public-ip'],
          ));
        }

        // 2. OS Login disabled (SSH key-based auth)
        const osLoginEnabled = (instance.metadata?.items ?? []).some((item: any) =>
          item.key === 'enable-oslogin' && item.value?.toLowerCase() === 'true',
        );
        if (!osLoginEnabled) {
          findings.push(this.finding(
            'Compute Engine instance does not use OS Login',
            `VM instance "${name}" (zone: ${zone}) does not have OS Login enabled. Without OS Login, SSH access is managed via project/instance metadata SSH keys, which bypass IAM-based access controls and MFA.`,
            'HIGH',
            { instance: name, zone, project },
            'Enable OS Login by setting the enable-oslogin=true metadata key. OS Login integrates SSH access with IAM and optionally enforces 2FA for SSH sessions.',
            ['compute', 'ssh', 'os-login'],
          ));
        }

        // 3. Serial port enabled
        const serialEnabled = (instance.metadata?.items ?? []).some((item: any) =>
          item.key === 'serial-port-enable' && (item.value === '1' || item.value?.toLowerCase() === 'true'),
        );
        if (serialEnabled) {
          findings.push(this.finding(
            'Compute Engine instance has serial port access enabled',
            `VM instance "${name}" (zone: ${zone}) has serial port (console) access enabled. Serial port access allows interactive debugging sessions that bypass normal authentication, potentially exposing credentials in the console output.`,
            'HIGH',
            { instance: name, zone, project },
            'Disable serial port access by setting serial-port-enable=false in instance metadata. Use OS Login or SSH keys for secure instance access instead.',
            ['compute', 'serial-port'],
          ));
        }

        // 4. Disk encryption (CMEK)
        const disks = instance.disks ?? [];
        const unencryptedDisks = disks.filter((d: any) => !d.diskEncryptionKey?.kmsKeyName);
        if (unencryptedDisks.length > 0 && disks.length > 0) {
          findings.push(this.finding(
            'Compute Engine instance disks do not use customer-managed encryption keys',
            `VM instance "${name}" (zone: ${zone}) has ${unencryptedDisks.length} disk(s) using Google-managed encryption. CMEK gives control over key lifecycle and enables key revocation.`,
            'LOW',
            { instance: name, zone, project, unencryptedDiskCount: unencryptedDisks.length },
            'Encrypt Compute Engine disks with a customer-managed key from Cloud KMS. Note: disks must be recreated from snapshots to apply CMEK.',
            ['compute', 'disk-encryption', 'cmek'],
          ));
        }

        // 5. No service account / default service account
        const saEmail = instance.serviceAccounts?.[0]?.email;
        if (!saEmail) {
          findings.push(this.finding(
            'Compute Engine instance has no service account attached',
            `VM instance "${name}" (zone: ${zone}) has no service account. Workloads running on this instance cannot authenticate to GCP APIs using ADC (Application Default Credentials).`,
            'MEDIUM',
            { instance: name, zone, project },
            'Attach a dedicated, least-privilege service account to the VM. Avoid attaching the default Compute Engine service account which has the Editor role.',
            ['compute', 'service-account'],
          ));
        } else if (saEmail.endsWith('-compute@developer.gserviceaccount.com')) {
          findings.push(this.finding(
            'Compute Engine instance uses the default Compute service account',
            `VM instance "${name}" (zone: ${zone}) uses the default Compute Engine service account "${saEmail}" which typically has the Editor role, granting broad write access to all GCP APIs.`,
            'HIGH',
            { instance: name, zone, project, serviceAccount: saEmail },
            'Create a dedicated service account with only the required roles for this VM\'s workload. Attach it to the instance and remove the default service account binding.',
            ['compute', 'service-account', 'least-privilege'],
          ));
        }

        // 6. Shielded VM not enabled
        const shieldedConfig = instance.shieldedInstanceConfig;
        if (!shieldedConfig?.enableSecureBoot || !shieldedConfig?.enableVtpm) {
          findings.push(this.finding(
            'Compute Engine instance does not use Shielded VM features',
            `VM instance "${name}" (zone: ${zone}) does not have Shielded VM features (Secure Boot, vTPM) enabled. Shielded VMs protect against rootkits, bootkits, and kernel-level malware.`,
            'MEDIUM',
            { instance: name, zone, project, secureBoot: shieldedConfig?.enableSecureBoot, vtpm: shieldedConfig?.enableVtpm },
            'Enable Shielded VM by setting enableSecureBoot=true and enableVtpm=true on the instance. Recreate the instance if the current machine type supports Shielded VM.',
            ['compute', 'shielded-vm'],
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
            findings.push(this.finding(
              'Firewall rule allows unrestricted inbound traffic from 0.0.0.0/0',
              `Firewall rule "${name}" in project "${project}" allows all ${protocol.toUpperCase()} traffic from any source. This exposes all instances matching the target to internet-based attacks.`,
              'CRITICAL',
              { rule: name, project, protocol, sourceRanges, direction: 'INGRESS' },
              'Restrict the source range to specific IP ranges or remove the rule. Use Identity-Aware Proxy (IAP) for SSH/RDP access instead of opening firewall rules to the internet.',
              ['compute', 'firewall', 'open-port'],
            ));
            continue;
          }

          for (const port of ports) {
            const portNum = parseInt(port.split('-')[0], 10);
            if (isNaN(portNum)) continue;

            if (portNum === 22) {
              findings.push(this.finding(
                'Firewall rule allows SSH (port 22) from any source',
                `Firewall rule "${name}" allows SSH access (TCP/22) from 0.0.0.0/0. Any internet-connected host can attempt to connect to instances matching this rule.`,
                'CRITICAL',
                { rule: name, project, port: '22', protocol: 'tcp' },
                'Remove the SSH firewall rule. Use Identity-Aware Proxy (IAP) Tunneling (gcloud compute ssh --tunnel-through-iap) which does not require a public IP or open firewall rule.',
                ['compute', 'firewall', 'ssh'],
              ));
            } else if (portNum === 3389) {
              findings.push(this.finding(
                'Firewall rule allows RDP (port 3389) from any source',
                `Firewall rule "${name}" allows RDP access (TCP/3389) from 0.0.0.0/0. Windows RDP exposed to the internet is a primary target for brute-force and ransomware attacks.`,
                'CRITICAL',
                { rule: name, project, port: '3389', protocol: 'tcp' },
                'Remove the RDP firewall rule. Use IAP Desktop for RDP access through Identity-Aware Proxy without exposing port 3389.',
                ['compute', 'firewall', 'rdp'],
              ));
            } else if (SENSITIVE_PORTS.includes(portNum)) {
              findings.push(this.finding(
                `Firewall rule exposes sensitive port ${portNum} to the internet`,
                `Firewall rule "${name}" allows inbound ${protocol.toUpperCase()} port ${portNum} from 0.0.0.0/0. Sensitive services exposed to the internet are at risk of exploitation.`,
                'HIGH',
                { rule: name, project, port: String(portNum), protocol },
                `Restrict firewall rule "${name}" to specific source IP ranges. Consider using VPC Service Controls or Private Service Connect to avoid exposing sensitive ports.`,
                ['compute', 'firewall', 'sensitive-port'],
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
        findings.push(this.finding(
          `Default firewall rule "${r.name}" is enabled`,
          `The default firewall rule "${r.name}" in project "${project}" is enabled and allows access from 0.0.0.0/0. Default rules are broad and should be replaced with more restrictive custom rules.`,
          'HIGH',
          { rule: r.name, project, direction: r.direction, sourceRanges: r.sourceRanges },
          `Disable the default rule "${r.name}" and create specific firewall rules that allow only required traffic from known source IP ranges or via IAP.`,
          ['compute', 'firewall', 'default-rule'],
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
        findings.push(this.finding(
          'Project uses the default VPC network',
          `The project "${project}" still uses the default VPC network. The default VPC is automatically created with permissive pre-populated firewall rules (allow SSH, RDP, ICMP from 0.0.0.0/0) and does not follow network segmentation best practices.`,
          'HIGH',
          { project, networkName: 'default', subnetMode: defaultVPC.autoCreateSubnetworks ? 'auto' : 'custom' },
          'Delete the default VPC and create custom VPCs with appropriately scoped subnets and firewall rules. Migrate all resources to the custom VPC.',
          ['compute', 'vpc', 'default-network'],
        ));
      }

      // Check for auto-mode VPCs (creates subnets in all regions automatically)
      const autoNetworks = networks.filter(n => n.autoCreateSubnetworks && n.name !== 'default');
      for (const net of autoNetworks) {
        findings.push(this.finding(
          'VPC network uses auto-mode subnet creation',
          `VPC network "${net.name}" in project "${project}" uses auto-mode which automatically creates subnets in all GCP regions. This results in unnecessarily broad network footprint and may create subnets in unintended regions.`,
          'MEDIUM',
          { project, network: net.name },
          'Migrate to custom-mode VPC where subnets are only created in regions where resources are intentionally deployed. This provides better network governance.',
          ['compute', 'vpc', 'auto-mode'],
        ));
      }

      // Check for VPCs with no subnets (orphaned)
      for (const net of networks) {
        if (net.subnetworks?.length === 0 && net.name !== 'default') {
          findings.push(this.finding(
            'Empty VPC network with no subnets',
            `VPC network "${net.name}" in project "${project}" has no subnets. Empty VPCs represent unused network resources.`,
            'LOW',
            { project, network: net.name },
            'Delete unused VPC networks to reduce network surface area and avoid accidental resource creation in the wrong network.',
            ['compute', 'vpc'],
          ));
        }
      }
    } catch { /* optional */ }
  }
}
