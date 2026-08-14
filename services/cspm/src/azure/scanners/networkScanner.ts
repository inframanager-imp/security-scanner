// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const EXCLUDED_SUBNET_NAMES = new Set([
  'gatewaysubnet',
  'azurefirewallsubnet',
  'azurefirewallmanagementsubnet',
  'azurebastionsubnet',
  'routeserversubnet',
]);

export class AzureNetworkScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-Network');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const networkClient = this.client.network();

      // ── Azure Firewall presence ───────────────────────────────────────────
      try {
        const firewalls: any[] = [];
        for await (const fw of networkClient.azureFirewalls.listAll()) firewalls.push(fw);

        if (firewalls.length === 0) {
          findings.push(this.emit(
            'azure_network_firewall_deployed',
            { firewallCount: 0 },
            {
              message: 'No Azure Firewall instances were found in this subscription. Without a centralised firewall, east-west and north-south traffic inspection relies entirely on NSG rules, which provide no layer-7 filtering, FQDN-based rules, or threat intelligence.',
            },
          ));
        } else {
          // Check for firewalls in a stopped (deallocated) state
          const stoppedFirewalls = firewalls.filter(fw => {
            // A deallocated firewall has no ipConfigurations or they are empty
            const ips = fw.ipConfigurations ?? [];
            return ips.length === 0 || !ips.some((ip: any) => ip.publicIPAddress?.id);
          });
          if (stoppedFirewalls.length > 0) {
            findings.push(this.emit(
              'azure_network_firewall_allocated',
              { count: stoppedFirewalls.length, names: stoppedFirewalls.map((f: any) => f.name) },
              {
                message: `${stoppedFirewalls.length} Azure Firewall instance(s) (${stoppedFirewalls.map((f: any) => f.name).join(', ')}) have no public IP configuration, indicating they may be deallocated. Traffic is not being inspected.`,
              },
            ));
          }

          // Check for firewalls using Basic SKU (limited features)
          const basicFirewalls = firewalls.filter((fw: any) => fw.sku?.tier === 'Basic');
          if (basicFirewalls.length > 0) {
            findings.push(this.emit(
              'azure_network_firewall_standard_or_premium_sku',
              { count: basicFirewalls.length, names: basicFirewalls.map((f: any) => f.name) },
              {
                message: `${basicFirewalls.length} Azure Firewall instance(s) are using the Basic SKU, which lacks threat intelligence filtering, IDPS (Premium), and full policy support.`,
              },
            ));
          }
        }
      } catch { /* firewall check optional */ }

      // ── Route Tables — improper default routes ────────────────────────────
      try {
        const routeTables: any[] = [];
        for await (const rt of networkClient.routeTables.listAll()) routeTables.push(rt);

        for (const rt of routeTables) {
          const rtName = rt.name ?? 'unknown';
          const rg     = rt.id?.split('/')[4] ?? 'unknown';
          const routes  = rt.routes ?? [];

          // Look for a 0.0.0.0/0 route that goes directly to Internet (not via a firewall NVA)
          const directInternetRoutes = routes.filter((r: any) =>
            r.addressPrefix === '0.0.0.0/0' &&
            r.nextHopType === 'Internet',
          );

          if (directInternetRoutes.length > 0) {
            findings.push(this.emit(
              'azure_network_route_table_no_direct_internet_default_route',
              {
                routeTable: rtName,
                resourceGroup: rg,
                routes: directInternetRoutes.map((r: any) => r.name),
                subnets: (rt.subnets ?? []).map((s: any) => s.id?.split('/').pop()),
              },
              {
                message: `Route table "${rtName}" has a 0.0.0.0/0 route with nextHopType "Internet". Subnets using this route table send all unmatched traffic directly to the internet, bypassing any Azure Firewall or NVA inspection.`,
              },
            ));
          }

          // Route table not associated with any subnet
          if ((rt.subnets ?? []).length === 0) {
            findings.push(this.emit(
              'azure_network_route_table_associated',
              { routeTable: rtName, resourceGroup: rg },
              {
                message: `Route table "${rtName}" is not attached to any subnet. It provides no traffic control and may be an orphaned resource.`,
              },
            ));
          }
        }
      } catch { /* route table check optional */ }

      // ── VNet — subnets with no NSG (network_subnet_nsg_associated) ────────
      try {
        const vnets: any[] = [];
        for await (const vnet of networkClient.virtualNetworks.listAll()) vnets.push(vnet);

        const unprotectedSubnets: string[] = [];
        for (const vnet of vnets) {
          for (const subnet of vnet.subnets ?? []) {
            // Skip Azure-managed subnets — they must not have NSGs
            const subnetName = (subnet.name ?? '').toLowerCase();
            if (EXCLUDED_SUBNET_NAMES.has(subnetName)) continue;

            if (!subnet.networkSecurityGroup?.id) {
              unprotectedSubnets.push(`${vnet.name}/${subnet.name}`);
            }
          }
        }

        if (unprotectedSubnets.length > 0) {
          findings.push(this.emit(
            'network_subnet_nsg_associated',
            { count: unprotectedSubnets.length, subnets: unprotectedSubnets.slice(0, 10) },
            {
              message: `${unprotectedSubnets.length} subnet(s) have no NSG attached: ${unprotectedSubnets.slice(0, 10).join(', ')}${unprotectedSubnets.length > 10 ? '...' : ''}. Resources in these subnets have no network-level access control.`,
            },
          ));
        }
      } catch { /* VNet check optional */ }

      // ── DDoS Protection (network_vnet_ddos_protection_enabled) ────────────
      try {
        const vnets: any[] = [];
        for await (const vnet of networkClient.virtualNetworks.listAll()) vnets.push(vnet);

        const unprotectedVnets = vnets.filter(
          v => !v.ddosProtectionPlan?.id || v.enableDdosProtection !== true,
        );

        if (unprotectedVnets.length > 0 && vnets.length > 0) {
          findings.push(this.emit(
            'network_vnet_ddos_protection_enabled',
            {
              count: unprotectedVnets.length,
              vnets: unprotectedVnets.slice(0, 10).map((v: any) => v.name),
            },
            {
              message: `${unprotectedVnets.length} of ${vnets.length} VNet(s) do not have Azure DDoS Protection Standard enabled: ${unprotectedVnets.slice(0, 5).map((v: any) => v.name).join(', ')}. Basic DDoS protection is automatic but insufficient for production workloads.`,
            },
          ));
        }
      } catch { /* DDoS check optional */ }

      // ── Bastion Host presence (network_bastion_host_exists) ───────────────
      try {
        const bastionHosts: any[] = [];
        for await (const bh of networkClient.bastionHosts.list()) bastionHosts.push(bh);

        if (bastionHosts.length === 0) {
          findings.push(this.emit(
            'network_bastion_host_exists',
            { bastionHostCount: 0 },
            {
              message: 'No Azure Bastion host was found in this subscription. Without Bastion, RDP/SSH access to VMs typically relies on public IPs or NSG rules opening management ports directly to the internet.',
            },
          ));
        }
      } catch { /* Bastion check optional */ }

      // ── Network Watcher coverage per location (network_watcher_enabled) ───
      let networkWatchers: any[] = [];
      try {
        for await (const nw of networkClient.networkWatchers.listAll()) networkWatchers.push(nw);

        const vnetLocationSet = new Set<string>();
        try {
          for await (const vnet of networkClient.virtualNetworks.listAll()) {
            if (vnet.location) vnetLocationSet.add(vnet.location.toLowerCase());
          }
        } catch { /* location discovery optional */ }

        const coveredLocations = new Set(networkWatchers.map((nw: any) => (nw.location ?? '').toLowerCase()));
        const missingLocations = [...vnetLocationSet].filter(loc => !coveredLocations.has(loc));

        if (vnetLocationSet.size > 0 && missingLocations.length > 0) {
          findings.push(this.emit(
            'network_watcher_enabled',
            { missingLocations },
            {
              message: `Network Watcher is not enabled for the following location(s) with deployed resources: ${missingLocations.join(', ')}.`,
            },
          ));
        }
      } catch { /* Network Watcher check optional */ }

      // ── Flow logs captured/sent + retention (per Network Watcher) ─────────
      try {
        for (const nw of networkWatchers) {
          const nwName = nw.name ?? 'unknown';
          const rg = nw.id?.split('/')[4] ?? 'unknown';

          let flowLogs: any[] = [];
          try {
            flowLogs = [];
            for await (const fl of networkClient.flowLogs.list(rg, nwName)) flowLogs.push(fl);
          } catch { continue; }

          if (flowLogs.length === 0) {
            findings.push(this.emit(
              'network_flow_log_captured_sent',
              { networkWatcher: nwName, resourceGroup: rg },
              {
                message: `Network Watcher "${nwName}" has no flow logs configured. Traffic through associated VNets/NSGs is not being captured for analysis.`,
              },
            ));
            continue;
          }

          const disabledLog = flowLogs.find((fl: any) => fl.enabled !== true);
          if (disabledLog) {
            findings.push(this.emit(
              'network_flow_log_captured_sent',
              { networkWatcher: nwName, resourceGroup: rg, flowLog: disabledLog.name },
              {
                message: `Network Watcher "${nwName}" has flow log "${disabledLog.name}" disabled.`,
              },
            ));
          } else {
            const missingAnalytics = flowLogs.find((fl: any) => {
              const analytics = fl.flowAnalyticsConfiguration?.networkWatcherFlowAnalyticsConfiguration;
              return !(analytics?.enabled && analytics?.workspaceResourceId);
            });
            if (missingAnalytics) {
              findings.push(this.emit(
                'network_flow_log_captured_sent',
                { networkWatcher: nwName, resourceGroup: rg, flowLog: missingAnalytics.name },
                {
                  message: `Network Watcher "${nwName}" has enabled flow log "${missingAnalytics.name}" that is not configured to send Traffic Analytics to a Log Analytics workspace.`,
                },
              ));
            }
          }

          // Retention — flag any enabled flow log with retention under 90 days (0 = unlimited, OK)
          const shortRetention = flowLogs.find((fl: any) =>
            fl.enabled === true &&
            (fl.retentionPolicy?.days ?? 0) !== 0 &&
            (fl.retentionPolicy?.days ?? 0) < 90,
          );
          if (shortRetention) {
            findings.push(this.emit(
              'network_flow_log_more_than_90_days',
              { networkWatcher: nwName, resourceGroup: rg, flowLog: shortRetention.name, retentionDays: shortRetention.retentionPolicy?.days },
              {
                message: `Network Watcher "${nwName}" flow log "${shortRetention.name}" has a retention policy of ${shortRetention.retentionPolicy?.days} day(s), less than the recommended 90 days.`,
              },
            ));
          }
        }
      } catch { /* flow log check optional */ }

    } catch (err) {
      findings.push(this.finding(
        'Azure Network scan error',
        `Could not complete Network scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Network resources.',
      ));
    }

    return findings;
  }
}
