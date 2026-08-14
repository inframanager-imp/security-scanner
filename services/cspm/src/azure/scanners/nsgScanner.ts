// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const SENSITIVE_PORTS = [1433, 3306, 5432, 27017, 6379, 5601, 9200, 8080, 443];
const OPEN_SOURCE_PREFIXES = new Set(['*', '0.0.0.0/0', 'Internet', 'Any']);

export class AzureNSGScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-NSG');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const networkClient = this.client.network();

    try {
      const nsgs: any[] = [];
      for await (const nsg of networkClient.networkSecurityGroups.listAll()) nsgs.push(nsg);

      // Track subscription-wide status for the four port-specific Prowler checks
      let sshOpen: any = null;
      let rdpOpen: any = null;
      let httpOpen: any = null;
      let udpOpen: any = null;

      for (const nsg of nsgs) {
        const nsgName = nsg.name ?? 'unknown';
        const rg      = nsg.id?.split('/')[4] ?? 'unknown';
        const rules   = nsg.securityRules ?? [];

        for (const rule of rules) {
          if (rule.access !== 'Allow' || rule.direction !== 'Inbound') continue;

          const srcPrefix = rule.sourceAddressPrefix ?? '';
          const isOpenToInternet = OPEN_SOURCE_PREFIXES.has(srcPrefix);
          if (!isOpenToInternet) continue;

          const protocol = (rule.protocol ?? '').toString();
          const destPortRange  = rule.destinationPortRange  ?? '';
          const destPortRanges = rule.destinationPortRanges ?? [];
          const allPorts       = [destPortRange, ...destPortRanges].filter(Boolean);

          const isAllPorts = allPorts.some(p => p === '*' || p === '0-65535');

          if (isAllPorts) {
            findings.push(this.emit(
              'azure_nsg_rule_unrestricted_inbound_all_ports',
              { nsg: nsgName, rule: rule.name, priority: rule.priority, resourceGroup: rg },
              {
                message: `NSG "${nsgName}" rule "${rule.name}" allows ALL inbound traffic from 0.0.0.0/0. This fully exposes all associated resources to the internet.`,
              },
            ));
          }

          const isTcpish = ['TCP', 'Tcp', '*'].includes(protocol) || isAllPorts;
          const isUdp = ['UDP', 'Udp'].includes(protocol);

          if (isUdp && !udpOpen) {
            // network_udp_internet_access_restricted: any UDP rule open to the internet fails
            udpOpen = { nsg: nsgName, rule: rule.name, resourceGroup: rg };
          }

          if (isTcpish) {
            for (const portSpec of allPorts.length > 0 ? allPorts : ['*']) {
              if (!sshOpen && this.portMatches(portSpec, 22)) {
                sshOpen = { nsg: nsgName, rule: rule.name, resourceGroup: rg };
              }
              if (!rdpOpen && this.portMatches(portSpec, 3389)) {
                rdpOpen = { nsg: nsgName, rule: rule.name, resourceGroup: rg };
              }
              if (!httpOpen && this.portMatches(portSpec, 80)) {
                httpOpen = { nsg: nsgName, rule: rule.name, resourceGroup: rg };
              }
            }
          }

          if (isAllPorts) continue;

          for (const portSpec of allPorts) {
            // Check if portSpec is a single port or range that includes sensitive ports
            const exposedSensitivePorts: number[] = [];
            for (const sp of SENSITIVE_PORTS) {
              if (this.portMatches(portSpec, sp)) exposedSensitivePorts.push(sp);
            }
            if (exposedSensitivePorts.length > 0) {
              findings.push(this.emit(
                'azure_nsg_rule_sensitive_port_exposed_to_internet',
                { nsg: nsgName, rule: rule.name, ports: exposedSensitivePorts, priority: rule.priority, resourceGroup: rg },
                {
                  message: `NSG "${nsgName}" rule "${rule.name}" allows inbound traffic from 0.0.0.0/0 on port(s): ${exposedSensitivePorts.join(', ')}. This exposes data-plane services to the public internet.`,
                },
              ));
            }
          }
        }

        // NSG not associated with any subnet or NIC (azure_nsg_associated)
        const hasSubnetAssoc = (nsg.subnets ?? []).length > 0;
        const hasNicAssoc    = (nsg.networkInterfaces ?? []).length > 0;
        if (!hasSubnetAssoc && !hasNicAssoc) {
          findings.push(this.emit(
            'azure_nsg_associated',
            { nsg: nsgName, resourceGroup: rg },
            {
              message: `NSG "${nsgName}" is not attached to any subnet or network interface. It provides no protection.`,
            },
          ));
        }
      }

      // ── Port-specific internet-access checks (Prowler-verbatim IDs) ────────
      // Only emitted when the condition is violated, consistent with the rest
      // of this codebase's finding model (findings represent problems found).
      if (sshOpen) {
        findings.push(this.emit('network_ssh_internet_access_restricted', sshOpen, {
          message: `NSG "${sshOpen.nsg}" rule "${sshOpen.rule}" allows SSH (port 22) inbound from the internet.`,
        }));
      }

      if (rdpOpen) {
        findings.push(this.emit('network_rdp_internet_access_restricted', rdpOpen, {
          message: `NSG "${rdpOpen.nsg}" rule "${rdpOpen.rule}" allows RDP (port 3389) inbound from the internet.`,
        }));
      }

      if (httpOpen) {
        findings.push(this.emit('network_http_internet_access_restricted', httpOpen, {
          message: `NSG "${httpOpen.nsg}" rule "${httpOpen.rule}" allows HTTP (port 80) inbound from the internet.`,
        }));
      }

      if (udpOpen) {
        findings.push(this.emit('network_udp_internet_access_restricted', udpOpen, {
          message: `NSG "${udpOpen.nsg}" rule "${udpOpen.rule}" allows UDP traffic inbound from the internet.`,
        }));
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure NSG scan error',
        `Could not complete NSG scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Network Contributor or Reader permissions.',
      ));
    }

    return findings;
  }

  private portMatches(spec: string, port: number): boolean {
    if (spec === '*') return true;
    if (spec.includes('-')) {
      const [lo, hi] = spec.split('-').map(Number);
      return !isNaN(lo) && !isNaN(hi) && port >= lo && port <= hi;
    }
    return Number(spec) === port;
  }
}
