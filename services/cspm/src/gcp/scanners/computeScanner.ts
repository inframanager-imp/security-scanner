// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const SENSITIVE_PORTS = [22, 3389, 5432, 3306, 1433, 6379, 27017, 9200, 8080, 8443];
const MIG_MIN_ZONES = 2;
const MAX_SNAPSHOT_AGE_DAYS = 90;

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
        this.checkSubnets(project, findings),
        // checkLoadBalancers reads the MIGs that checkInstanceGroups collects (for the
        // load-balancer-attachment check), so it must run after that scan completes rather
        // than concurrently with it.
        this.checkInstanceGroups(project, findings).then(() => this.checkLoadBalancers(project, findings)),
        this.checkImages(project, findings),
        this.checkSnapshots(project, findings),
        this.checkProjectOsLogin(project, findings),
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
        const isGke = typeof name === 'string' && name.startsWith('gke-');
        const metadataItems: any[] = instance.metadata?.items ?? [];
        const getMeta = (key: string) => metadataItems.find((i) => i.key === key)?.value;

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
            {
              message: `VM instance "${name}" (zone: ${zone}) has a public IP: ${publicIPs.join(', ')}. Public IPs expose the instance directly to internet-based attacks.`,
            },
          ));
        }

        // 2. OS Login disabled (instance-level metadata)
        const osLoginEnabled = getMeta('enable-oslogin')?.toLowerCase() === 'true';
        if (!osLoginEnabled) {
          findings.push(this.emit(
            'compute_instance_metadata_os_login_enabled',
            { instance: name, zone, project },
            {
              message: `VM instance "${name}" (zone: ${zone}) does not have OS Login enabled. Without OS Login, SSH access is managed via project/instance metadata SSH keys, which bypass IAM-based access controls and MFA.`,
            },
          ));
        }

        // 3. Serial port enabled (two checkIds: product-invented + Prowler-ported, same condition)
        const serialValue = getMeta('serial-port-enable');
        const serialEnabled = serialValue === '1' || serialValue?.toLowerCase() === 'true';
        if (serialEnabled) {
          findings.push(this.emit(
            'compute_instance_serial_port_metadata_disabled',
            { instance: name, zone, project },
            {
              message: `VM instance "${name}" (zone: ${zone}) has serial port (console) access enabled. Serial port access allows interactive debugging sessions that bypass normal authentication, potentially exposing credentials in the console output.`,
            },
          ));
          findings.push(this.emit(
            'compute_instance_serial_ports_in_use',
            { instance: name, zone, project },
            {
              message: `VM Instance ${name} has Enable Connecting to Serial Ports set to on.`,
            },
          ));
        }

        // 4. Disk encryption (CMEK)
        const disks: any[] = instance.disks ?? [];
        const unencryptedDisks = disks.filter((d: any) => !d.diskEncryptionKey?.kmsKeyName);
        if (unencryptedDisks.length > 0 && disks.length > 0) {
          findings.push(this.emit(
            'compute_instance_disks_cmek_encrypted',
            { instance: name, zone, project, unencryptedDiskCount: unencryptedDisks.length },
            {
              message: `VM instance "${name}" (zone: ${zone}) has ${unencryptedDisks.length} disk(s) using Google-managed encryption. CMEK gives control over key lifecycle and enables key revocation.`,
            },
          ));
        }

        // 4b. Disk encryption with CSEK (Prowler: compute_instance_encryption_with_csek_enabled)
        // disksEncryption uses the sha256 hash presence on diskEncryptionKey as the CSEK signal,
        // matching Prowler's compute_service.py disks_encryption tuple semantics.
        const csekUnencrypted = disks.filter((d: any) => !d.diskEncryptionKey?.sha256);
        if (disks.length > 0 && csekUnencrypted.length > 0) {
          findings.push(this.emit(
            'compute_instance_encryption_with_csek_enabled',
            { instance: name, zone, project, unencryptedDisks: csekUnencrypted.map((d: any) => d.deviceName) },
            {
              message: `The VM Instance ${name} has the following unencrypted disks: '${csekUnencrypted.map((d: any) => d.deviceName).join(', ')}'.`,
            },
          ));
        }

        // 5. No service account / default service account
        const serviceAccounts: any[] = instance.serviceAccounts ?? [];
        const saEmail = serviceAccounts[0]?.email;
        const usesDefaultSa = !!saEmail && saEmail.endsWith('-compute@developer.gserviceaccount.com') && !isGke;
        if (!saEmail) {
          findings.push(this.emit(
            'compute_instance_service_account_configured',
            { instance: name, zone, project },
            {
              message: `VM instance "${name}" (zone: ${zone}) has no service account. Workloads running on this instance cannot authenticate to GCP APIs using ADC (Application Default Credentials).`,
            },
          ));
        } else if (usesDefaultSa) {
          findings.push(this.emit(
            'compute_instance_default_service_account_in_use',
            { instance: name, zone, project, serviceAccount: saEmail },
            {
              message: `The default service account is configured to be used with VM Instance ${name}.`,
            },
          ));

          const scopes: string[] = serviceAccounts[0]?.scopes ?? [];
          if (scopes.includes('https://www.googleapis.com/auth/cloud-platform')) {
            findings.push(this.emit(
              'compute_instance_default_service_account_in_use_with_full_api_access',
              { instance: name, zone, project, serviceAccount: saEmail },
              {
                message: `The VM Instance ${name} is configured to use the default service account with full access to all cloud APIs.`,
              },
            ));
          }
        }

        // 6. Shielded VM checks: two distinct Prowler-derived conditions.
        const shieldedConfig = instance.shieldedInstanceConfig;
        const secureBoot = !!shieldedConfig?.enableSecureBoot;
        const vtpm = !!shieldedConfig?.enableVtpm;
        const integrityMonitoring = !!shieldedConfig?.enableIntegrityMonitoring;
        if (!secureBoot || !vtpm) {
          findings.push(this.emit(
            'compute_instance_shielded_secure_boot_vtpm_enabled',
            { instance: name, zone, project, secureBoot, vtpm },
            {
              message: `VM instance "${name}" (zone: ${zone}) does not have Shielded VM features (Secure Boot, vTPM) enabled. Shielded VMs protect against rootkits, bootkits, and kernel-level malware.`,
            },
          ));
        }
        if (!vtpm || !integrityMonitoring) {
          findings.push(this.emit(
            'compute_instance_shielded_vm_enabled',
            { instance: name, zone, project, vtpm, integrityMonitoring },
            {
              message: `VM Instance ${name} doesn't have vTPM and Integrity Monitoring set to on.`,
            },
          ));
        }

        // 7. Automatic restart (preemptible/Spot VMs cannot support it and are treated as FAIL, per Prowler)
        const scheduling = instance.scheduling ?? {};
        const preemptible = !!instance.preemptible || !!scheduling.preemptible;
        const provisioningModel = scheduling.provisioningModel ?? 'STANDARD';
        const isSpot = provisioningModel === 'SPOT';
        const automaticRestart = scheduling.automaticRestart !== false; // GCP default is true when unset
        if (preemptible || isSpot || !automaticRestart) {
          findings.push(this.emit(
            'compute_instance_automatic_restart_enabled',
            { instance: name, zone, project, preemptible, provisioningModel },
            {
              message: (preemptible || isSpot)
                ? `VM Instance ${name} is a Preemptible or Spot instance, which cannot have Automatic Restart enabled by design.`
                : `VM Instance ${name} does not have Automatic Restart enabled.`,
            },
          ));
        }

        // 8. Block project-wide SSH keys
        const blockProjectSshKeys = getMeta('block-project-ssh-keys')?.toLowerCase() === 'true';
        if (!blockProjectSshKeys) {
          findings.push(this.emit(
            'compute_instance_block_project_wide_ssh_keys_disabled',
            { instance: name, zone, project },
            {
              message: `The VM Instance ${name} is making use of common/shared project-wide SSH key(s).`,
            },
          ));
        }

        // 9. Confidential computing
        if (!instance.confidentialInstanceConfig?.enableConfidentialCompute) {
          findings.push(this.emit(
            'compute_instance_confidential_computing_enabled',
            { instance: name, zone, project },
            {
              message: `VM Instance ${name} does not have Confidential Computing enabled.`,
            },
          ));
        }

        // 10. Deletion protection
        if (!instance.deletionProtection) {
          findings.push(this.emit(
            'compute_instance_deletion_protection_enabled',
            { instance: name, zone, project },
            {
              message: `VM Instance ${name} does not have deletion protection enabled.`,
            },
          ));
        }

        // 11. Disk auto-delete
        const autoDeleteDisks = disks.filter((d: any) => d.autoDelete).map((d: any) => d.deviceName);
        if (autoDeleteDisks.length > 0) {
          findings.push(this.emit(
            'compute_instance_disk_auto_delete_disabled',
            { instance: name, zone, project, autoDeleteDisks },
            {
              message: `VM Instance ${name} has auto-delete enabled for the following disks: ${autoDeleteDisks.join(', ')}.`,
            },
          ));
        }

        // 12. IP forwarding (GKE instances excluded, matching Prowler)
        if (instance.canIpForward && !isGke) {
          findings.push(this.emit(
            'compute_instance_ip_forwarding_is_enabled',
            { instance: name, zone, project },
            {
              message: `The IP Forwarding of VM Instance ${name} is enabled.`,
            },
          ));
        }

        // 13. On-host maintenance = MIGRATE (preemptible/Spot excluded, matching Prowler)
        const onHostMaintenance = scheduling.onHostMaintenance ?? 'MIGRATE';
        if (onHostMaintenance !== 'MIGRATE' && !preemptible && !isSpot) {
          findings.push(this.emit(
            'compute_instance_on_host_maintenance_migrate',
            { instance: name, zone, project, onHostMaintenance },
            {
              message: `VM Instance ${name} has On Host Maintenance set to ${onHostMaintenance} instead of MIGRATE.`,
            },
          ));
        }

        // 14. Preemptible/Spot VM in use
        if (preemptible || isSpot) {
          findings.push(this.emit(
            'compute_instance_preemptible_vm_disabled',
            { instance: name, zone, project, preemptible, provisioningModel },
            {
              message: `VM Instance ${name} is configured as ${preemptible ? 'preemptible' : 'Spot VM'}.`,
            },
          ));
        }

        // 15. Single network interface (GKE instances with multiple NICs are informational only, not failed)
        const nicCount = (instance.networkInterfaces ?? []).length;
        if (nicCount > 1 && !isGke) {
          findings.push(this.emit(
            'compute_instance_single_network_interface',
            { instance: name, zone, project, interfaceCount: nicCount },
            {
              message: `VM Instance ${name} has ${nicCount} network interfaces.`,
            },
          ));
        }

        // 16. Suspended instance with persistent disks still attached
        if ((instance.status === 'SUSPENDED' || instance.status === 'SUSPENDING') && disks.length > 0) {
          findings.push(this.emit(
            'compute_instance_suspended_without_persistent_disks',
            { instance: name, zone, project, status: instance.status, diskCount: disks.length },
            {
              message: `VM Instance ${name} is ${String(instance.status).toLowerCase()} with ${disks.length} persistent disk(s) attached.`,
            },
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

        let opensSsh = false;
        let opensRdp = false;

        // Check for any allowed ports
        for (const allowed of rule.allowed ?? []) {
          const protocol = allowed.IPProtocol ?? '';
          const ports    = allowed.ports ?? [];

          // All traffic (no port restriction) -- also implies SSH/RDP exposure
          if ((ports.length === 0 && (protocol === 'tcp' || protocol === 'udp' || protocol === 'all')) || protocol === 'all') {
            opensSsh = true;
            opensRdp = true;
            findings.push(this.emit(
              'compute_firewall_open_ingress_from_internet',
              { rule: name, project, protocol, sourceRanges, direction: 'INGRESS' },
              {
                message: `Firewall rule "${name}" in project "${project}" allows all ${protocol.toUpperCase()} traffic from any source. This exposes all instances matching the target to internet-based attacks.`,
              },
            ));
            continue;
          }

          for (const port of ports) {
            const portMatches = (target: number) => {
              if (port.includes('-')) {
                const [lower, higher] = port.split('-').map((p: string) => parseInt(p, 10));
                return !isNaN(lower) && !isNaN(higher) && lower <= target && higher >= target;
              }
              return parseInt(port, 10) === target;
            };

            if (protocol === 'tcp' && portMatches(22)) opensSsh = true;
            if (protocol === 'tcp' && portMatches(3389)) opensRdp = true;

            const portNum = parseInt(port.split('-')[0], 10);
            if (isNaN(portNum)) continue;

            if (portNum === 22) {
              findings.push(this.emit(
                'compute_firewall_ssh_exposed_generic',
                { rule: name, project, port: '22', protocol: 'tcp' },
                {
                  message: `Firewall rule "${name}" allows SSH access (TCP/22) from 0.0.0.0/0. Any internet-connected host can attempt to connect to instances matching this rule.`,
                },
              ));
            } else if (portNum === 3389) {
              findings.push(this.emit(
                'compute_firewall_rdp_exposed_generic',
                { rule: name, project, port: '3389', protocol: 'tcp' },
                {
                  message: `Firewall rule "${name}" allows RDP access (TCP/3389) from 0.0.0.0/0. Windows RDP exposed to the internet is a primary target for brute-force and ransomware attacks.`,
                },
              ));
            } else if (SENSITIVE_PORTS.includes(portNum)) {
              findings.push(this.emit(
                'compute_firewall_sensitive_port_exposed',
                { rule: name, project, port: String(portNum), protocol },
                {
                  message: `Firewall rule "${name}" allows inbound ${protocol.toUpperCase()} port ${portNum} from 0.0.0.0/0. Sensitive services exposed to the internet are at risk of exploitation.`,
                  remediation: `Restrict firewall rule "${name}" to specific source IP ranges. Consider using VPC Service Controls or Private Service Connect to avoid exposing sensitive ports.`,
                },
              ));
            }
          }
        }

        // Prowler-ported exact checks (one PASS/FAIL verdict per rule; we only emit on FAIL)
        if (opensSsh) {
          findings.push(this.emit(
            'compute_firewall_ssh_access_from_the_internet_allowed',
            { rule: name, project, sourceRanges },
            {
              message: `Firewall ${name} does exposes port 22 (SSH) to the internet.`,
            },
          ));
        }
        if (opensRdp) {
          findings.push(this.emit(
            'compute_firewall_rdp_access_from_the_internet_allowed',
            { rule: name, project, sourceRanges },
            {
              message: `Firewall ${name} does exposes port 3389 (RDP) to the internet.`,
            },
          ));
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
          {
            message: `The default firewall rule "${r.name}" in project "${project}" is enabled and allows access from 0.0.0.0/0. Default rules are broad and should be replaced with more restrictive custom rules.`,
          },
        ));
      }
    } catch { /* optional */ }
  }

  private async checkVPCNetworks(project: string, findings: ScanningResult[]): Promise<void> {
    try {
      const compute = this.client.compute();
      const res     = await compute.networks.list({ project });
      const networks = res.data.items ?? [];

      // Check if default VPC is used (Prowler: compute_network_default_in_use)
      const defaultVPC = networks.find(n => n.name === 'default');
      if (defaultVPC) {
        findings.push(this.emit(
          'compute_network_default_in_use',
          { project, networkName: 'default' },
          {
            message: `Default network is in use in project ${project}.`,
          },
        ));
      }

      // Check for auto-mode VPCs (creates subnets in all regions automatically)
      const autoNetworks = networks.filter(n => n.autoCreateSubnetworks && n.name !== 'default');
      for (const net of autoNetworks) {
        findings.push(this.emit(
          'compute_network_auto_mode_subnet_creation',
          { project, network: net.name },
          {
            message: `VPC network "${net.name}" in project "${project}" uses auto-mode which automatically creates subnets in all GCP regions. This results in unnecessarily broad network footprint and may create subnets in unintended regions.`,
          },
        ));
      }

      // Check for VPCs with no subnets (orphaned)
      for (const net of networks) {
        if (net.subnetworks?.length === 0 && net.name !== 'default') {
          findings.push(this.emit(
            'compute_network_empty_vpc',
            { project, network: net.name },
            {
              message: `VPC network "${net.name}" in project "${project}" has no subnets. Empty VPCs represent unused network resources.`,
            },
          ));
        }
      }

      // Legacy network mode (Prowler: compute_network_not_legacy)
      // "autoCreateSubnetworks" is absent entirely on legacy (non-subnetted) networks.
      for (const net of networks) {
        if (net.autoCreateSubnetworks === undefined && net.autoCreateSubnetworks !== null) {
          findings.push(this.emit(
            'compute_network_not_legacy',
            { project, network: net.name },
            {
              message: `Legacy network ${net.name} exists.`,
            },
          ));
        }
      }

      // DNS logging for each network (Prowler: compute_network_dns_logging_enabled)
      try {
        const dns = this.client.dns();
        const policiesRes = await dns.policies.list({ project });
        const policies = policiesRes.data.policies ?? [];
        for (const net of networks) {
          const covered = policies.some((p) =>
            p.enableLogging && (p.networks ?? []).some((n) => n.networkUrl?.split('/').pop() === net.name),
          );
          if (!covered) {
            findings.push(this.emit(
              'compute_network_dns_logging_enabled',
              { project, network: net.name },
              {
                message: `Network ${net.name} does not have DNS logging enabled.`,
              },
            ));
          }
        }
      } catch { /* optional: Cloud DNS API may not be enabled on the project */ }
    } catch { /* optional */ }
  }

  private async checkSubnets(project: string, findings: ScanningResult[]): Promise<void> {
    try {
      const compute = this.client.compute();
      const res = await compute.subnetworks.aggregatedList({ project, maxResults: 500 });
      const aggregated = res.data.items ?? {};

      const subnets: any[] = [];
      for (const scope of Object.values(aggregated)) {
        subnets.push(...((scope as any).subnetworks ?? []));
      }

      for (const subnet of subnets) {
        const name = subnet.name ?? 'unknown';
        const network = subnet.network?.split('/').pop() ?? 'unknown';
        if (!subnet.enableFlowLogs) {
          findings.push(this.emit(
            'compute_subnet_flow_logs_enabled',
            { subnet: name, network, project, region: subnet.region?.split('/').pop() },
            {
              message: `Subnet ${name} in network ${network} does not have flow logs enabled.`,
            },
          ));
        }
      }
    } catch { /* optional */ }
  }

  private async checkInstanceGroups(project: string, findings: ScanningResult[]): Promise<void> {
    try {
      const compute = this.client.compute();
      const res = await compute.instanceGroupManagers.aggregatedList({ project, maxResults: 500 });
      const aggregated = res.data.items ?? {};

      for (const [scopeKey, scoped] of Object.entries(aggregated)) {
        const migs: any[] = (scoped as any).instanceGroupManagers ?? [];
        const isRegional = scopeKey.startsWith('regions/');
        const scopeName = scopeKey.split('/').pop();

        for (const mig of migs) {
          const name = mig.name ?? 'unknown';
          const zones: string[] = isRegional
            ? (mig.distributionPolicy?.zones ?? []).map((z: any) => z.zone?.split('/').pop()).filter(Boolean)
            : [scopeName];
          const zoneCount = zones.length || 1;

          // Autohealing
          const policies: any[] = mig.autoHealingPolicies ?? [];
          const hasValidHealthCheck = policies.some((p) => p.healthCheck);
          if (policies.length === 0 || !hasValidHealthCheck) {
            findings.push(this.emit(
              'compute_instance_group_autohealing_enabled',
              { mig: name, project, scope: scopeName, isRegional },
              {
                message: policies.length === 0
                  ? `Managed Instance Group ${name} does not have autohealing enabled.`
                  : `Managed Instance Group ${name} has autohealing configured but is missing a valid health check reference.`,
              },
            ));
          }

          // Multiple zones (min 2, matching Prowler's default mig_min_zones)
          if (zoneCount < MIG_MIN_ZONES) {
            findings.push(this.emit(
              'compute_instance_group_multiple_zones',
              { mig: name, project, scope: scopeName, isRegional, zoneCount, zones },
              {
                message: isRegional
                  ? `Managed Instance Group ${name} is a regional MIG but only spans ${zoneCount} zone(s) (${zones.join(', ')}), minimum required is ${MIG_MIN_ZONES}.`
                  : `Managed Instance Group ${name} spans only ${zones.join(', ')}, consider converting to a regional MIG for high availability.`,
              },
            ));
          }

          // Load balancer attachment (compute_instance_group_load_balancer_attached) is
          // checked in checkLoadBalancers() via a shared backend-group lookup; see there.
        }

        // Stash for cross-referencing from checkLoadBalancers
        this._pendingMigs.push(...migs.map((mig: any) => ({ ...mig, isRegional, scopeName })));
      }
    } catch { /* optional */ }
  }

  /** MIGs discovered by checkInstanceGroups(), consumed by checkLoadBalancers() to test backend attachment. */
  private _pendingMigs: any[] = [];

  private async checkLoadBalancers(project: string, findings: ScanningResult[]): Promise<void> {
    try {
      const compute = this.client.compute();

      const loadBalancedGroups = new Set<string>();
      try {
        const backendRes = await compute.backendServices.list({ project });
        for (const bs of backendRes.data.items ?? []) {
          for (const backend of bs.backends ?? []) {
            const groupUrl = backend.group ?? '';
            if (groupUrl) loadBalancedGroups.add(groupUrl.split('/').pop() as string);
          }
        }
      } catch { /* optional */ }

      // Regional backend services also count as load-balancer attachment (Prowler checks both).
      try {
        const regions = new Set<string>();
        for (const mig of this._pendingMigs) {
          if (mig.isRegional && mig.scopeName) regions.add(mig.scopeName);
        }
        await Promise.all([...regions].map(async (region) => {
          try {
            const regionalRes = await compute.regionBackendServices.list({ project, region });
            for (const bs of regionalRes.data.items ?? []) {
              for (const backend of bs.backends ?? []) {
                const groupUrl = backend.group ?? '';
                if (groupUrl) loadBalancedGroups.add(groupUrl.split('/').pop() as string);
              }
            }
          } catch { /* optional */ }
        }));
      } catch { /* optional */ }

      // Global URL maps -> backend services -> logging
      try {
        const urlMapsRes = await compute.urlMaps.list({ project });
        for (const urlMap of urlMapsRes.data.items ?? []) {
          if (!urlMap.defaultService) continue;
          const backendServiceName = urlMap.defaultService.split('/').pop() as string;
          try {
            const bsRes = await compute.backendServices.get({ project, backendService: backendServiceName });
            const logging = !!bsRes.data.logConfig?.enable;
            if (!logging) {
              findings.push(this.emit(
                'compute_loadbalancer_logging_enabled',
                { loadBalancer: urlMap.name, project, backendService: backendServiceName },
                {
                  message: `LoadBalancer ${urlMap.name} does not have logging enabled.`,
                },
              ));
            }
          } catch { /* optional */ }
        }
      } catch { /* optional */ }

      // Regional MIG load-balancer attachment check (uses backend-group set gathered above)
      for (const mig of this._pendingMigs) {
        const attached = loadBalancedGroups.has(mig.name);
        if (!attached) {
          findings.push(this.emit(
            'compute_instance_group_load_balancer_attached',
            { mig: mig.name, project, scope: mig.scopeName, isRegional: mig.isRegional },
            {
              message: `Managed Instance Group ${mig.name} is not attached to any load balancer.`,
            },
          ));
        }
      }
      this._pendingMigs = [];
    } catch { /* optional */ }
  }

  private async checkImages(project: string, findings: ScanningResult[]): Promise<void> {
    try {
      const compute = this.client.compute();
      const res = await compute.images.list({ project });
      const images = res.data.items ?? [];

      for (const image of images) {
        const name = image.name ?? 'unknown';
        try {
          const policyRes = await compute.images.getIamPolicy({ project, resource: name });
          const publiclyShared = (policyRes.data.bindings ?? []).some((b) =>
            (b.members ?? []).includes('allAuthenticatedUsers'),
          );
          if (publiclyShared) {
            findings.push(this.emit(
              'compute_image_not_publicly_shared',
              { image: name, project },
              {
                message: `Compute Engine disk image ${name} is publicly shared with allAuthenticatedUsers.`,
              },
            ));
          }
        } catch { /* per-image IAM lookup is best-effort */ }
      }
    } catch { /* optional */ }
  }

  private async checkSnapshots(project: string, findings: ScanningResult[]): Promise<void> {
    try {
      const compute = this.client.compute();
      const res = await compute.snapshots.list({ project });
      const snapshots = res.data.items ?? [];
      const now = Date.now();

      for (const snapshot of snapshots) {
        const name = snapshot.name ?? 'unknown';
        if (!snapshot.creationTimestamp) {
          findings.push(this.emit(
            'compute_snapshot_not_outdated',
            { snapshot: name, project },
            {
              message: `Disk snapshot ${name} timestamp could not be retrieved and cannot be evaluated for age.`,
            },
          ));
          continue;
        }
        const ageDays = Math.floor((now - new Date(snapshot.creationTimestamp).getTime()) / (1000 * 60 * 60 * 24));
        if (ageDays > MAX_SNAPSHOT_AGE_DAYS) {
          findings.push(this.emit(
            'compute_snapshot_not_outdated',
            { snapshot: name, project, ageDays },
            {
              message: `Disk snapshot ${name} is ${ageDays} days old, exceeding the ${MAX_SNAPSHOT_AGE_DAYS} day threshold.`,
            },
          ));
        }
      }
    } catch { /* optional */ }
  }

  private async checkProjectOsLogin(project: string, findings: ScanningResult[]): Promise<void> {
    try {
      const compute = this.client.compute();
      const res = await compute.projects.get({ project });
      const items: any[] = res.data.commonInstanceMetadata?.items ?? [];
      const getMeta = (key: string) => items.find((i) => i.key === key)?.value;

      const osLoginEnabled = getMeta('enable-oslogin')?.toLowerCase() === 'true';
      if (!osLoginEnabled) {
        findings.push(this.emit(
          'compute_project_os_login_enabled',
          { project },
          {
            message: `Project ${project} does not have OS Login enabled.`,
          },
        ));
      }

      const osLogin2faEnabled = getMeta('enable-oslogin-2fa')?.toLowerCase() === 'true';
      if (!osLogin2faEnabled) {
        findings.push(this.emit(
          'compute_project_os_login_2fa_enabled',
          { project },
          {
            message: `Project ${project} does not have OS Login 2FA enabled.`,
          },
        ));
      }
    } catch { /* optional */ }
  }
}
