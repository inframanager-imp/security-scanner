import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

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
            { message: 'No Azure Firewall instances were found in this subscription. Without a centralised firewall, east-west and north-south traffic inspection relies entirely on NSG rules, which provide no layer-7 filtering, FQDN-based rules, or threat intelligence.' },
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
              { message: `${stoppedFirewalls.length} Azure Firewall instance(s) (${stoppedFirewalls.map((f: any) => f.name).join(', ')}) have no public IP configuration, indicating they may be deallocated. Traffic is not being inspected.` },
            ));
          }

          // Check for firewalls using Basic SKU (limited features)
          const basicFirewalls = firewalls.filter((fw: any) => fw.sku?.tier === 'Basic');
          if (basicFirewalls.length > 0) {
            findings.push(this.emit(
              'azure_network_firewall_standard_or_premium_sku',
              { count: basicFirewalls.length, names: basicFirewalls.map((f: any) => f.name) },
              { message: `${basicFirewalls.length} Azure Firewall instance(s) are using the Basic SKU, which lacks threat intelligence filtering, IDPS (Premium), and full policy support.` },
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
              { message: `Route table "${rtName}" has a 0.0.0.0/0 route with nextHopType "Internet". Subnets using this route table send all unmatched traffic directly to the internet, bypassing any Azure Firewall or NVA inspection.` },
            ));
          }

          // Route table not associated with any subnet
          if ((rt.subnets ?? []).length === 0) {
            findings.push(this.emit(
              'azure_network_route_table_associated',
              { routeTable: rtName, resourceGroup: rg },
              { message: `Route table "${rtName}" is not attached to any subnet. It provides no traffic control and may be an orphaned resource.` },
            ));
          }
        }
      } catch { /* route table check optional */ }

      // ── VNet — subnets with no NSG ────────────────────────────────────────
      try {
        const vnets: any[] = [];
        for await (const vnet of networkClient.virtualNetworks.listAll()) vnets.push(vnet);

        const unprotectedSubnets: string[] = [];
        for (const vnet of vnets) {
          for (const subnet of vnet.subnets ?? []) {
            // Skip gateway and AzureFirewall subnets — they must not have NSGs
            const subnetName = (subnet.name ?? '').toLowerCase();
            if (
              subnetName === 'gatewaysubnet' ||
              subnetName === 'azurefirewallsubnet' ||
              subnetName === 'azurebastionsubnet'
            ) continue;

            if (!subnet.networkSecurityGroup?.id) {
              unprotectedSubnets.push(`${vnet.name}/${subnet.name}`);
            }
          }
        }

        if (unprotectedSubnets.length > 0) {
          findings.push(this.emit(
            'network_subnet_nsg_associated',
            { count: unprotectedSubnets.length, subnets: unprotectedSubnets.slice(0, 10) },
            { message: `${unprotectedSubnets.length} subnet(s) have no NSG attached: ${unprotectedSubnets.slice(0, 10).join(', ')}${unprotectedSubnets.length > 10 ? '...' : ''}. Resources in these subnets have no network-level access control.` },
          ));
        }
      } catch { /* VNet check optional */ }

      // ── DDoS Protection ───────────────────────────────────────────────────
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
            { message: `${unprotectedVnets.length} of ${vnets.length} VNet(s) do not have Azure DDoS Protection Standard enabled: ${unprotectedVnets.slice(0, 5).map((v: any) => v.name).join(', ')}. Basic DDoS protection is automatic but insufficient for production workloads.` },
          ));
        }
      } catch { /* DDoS check optional */ }

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
