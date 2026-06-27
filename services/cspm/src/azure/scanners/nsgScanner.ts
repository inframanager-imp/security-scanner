import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const SENSITIVE_PORTS = [22, 3389, 1433, 3306, 5432, 27017, 6379, 5601, 9200, 8080, 443, 80];

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

      for (const nsg of nsgs) {
        const nsgName = nsg.name ?? 'unknown';
        const rg      = nsg.id?.split('/')[4] ?? 'unknown';
        const rules   = nsg.securityRules ?? [];

        for (const rule of rules) {
          if (rule.access !== 'Allow' || rule.direction !== 'Inbound') continue;

          const srcPrefix = rule.sourceAddressPrefix ?? '';
          const isOpenToInternet =
            srcPrefix === '*' ||
            srcPrefix === '0.0.0.0/0' ||
            srcPrefix === 'Internet' ||
            srcPrefix === 'Any';

          if (!isOpenToInternet) continue;

          const destPortRange  = rule.destinationPortRange  ?? '';
          const destPortRanges = rule.destinationPortRanges ?? [];
          const allPorts       = [destPortRange, ...destPortRanges].filter(Boolean);

          const isAllPorts = allPorts.some(p => p === '*' || p === '0-65535');

          if (isAllPorts) {
            findings.push(this.finding(
              'NSG rule allows unrestricted inbound traffic from internet',
              `NSG "${nsgName}" rule "${rule.name}" allows ALL inbound traffic from 0.0.0.0/0. This fully exposes all associated resources to the internet.`,
              'CRITICAL',
              { nsg: nsgName, rule: rule.name, priority: rule.priority, resourceGroup: rg },
              'Remove this rule immediately. Replace with specific source IP ranges and only open required ports.',
              ['nsg', 'network', 'internet-exposure'],
            ));
            continue;
          }

          for (const portSpec of allPorts) {
            // Check if portSpec is a single port or range that includes sensitive ports
            const exposedSensitivePorts: number[] = [];
            for (const sp of SENSITIVE_PORTS) {
              if (this.portMatches(portSpec, sp)) exposedSensitivePorts.push(sp);
            }
            if (exposedSensitivePorts.length > 0) {
              const isCritical = [22, 3389, 1433].some(p => exposedSensitivePorts.includes(p));
              findings.push(this.finding(
                `NSG rule exposes sensitive port(s) to the internet`,
                `NSG "${nsgName}" rule "${rule.name}" allows inbound traffic from 0.0.0.0/0 on port(s): ${exposedSensitivePorts.join(', ')}. This exposes management/data plane services to the public internet.`,
                isCritical ? 'CRITICAL' : 'HIGH',
                { nsg: nsgName, rule: rule.name, ports: exposedSensitivePorts, priority: rule.priority, resourceGroup: rg },
                `Restrict the source address prefix to specific trusted IP ranges. For SSH (22) and RDP (3389), use Azure Bastion or Just-In-Time access instead.`,
                ['nsg', 'network', 'internet-exposure'],
              ));
            }
          }
        }

        // NSG not associated with any subnet or NIC
        const hasSubnetAssoc = (nsg.subnets ?? []).length > 0;
        const hasNicAssoc    = (nsg.networkInterfaces ?? []).length > 0;
        if (!hasSubnetAssoc && !hasNicAssoc) {
          findings.push(this.finding(
            'Network Security Group is not associated with any subnet or NIC',
            `NSG "${nsgName}" is not attached to any subnet or network interface. It provides no protection.`,
            'LOW',
            { nsg: nsgName, resourceGroup: rg },
            'Associate the NSG with the appropriate subnet(s) or delete it if no longer needed.',
            ['nsg', 'network'],
          ));
        }
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
