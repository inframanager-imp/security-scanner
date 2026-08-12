// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  NetworkFirewallClient,
  ListFirewallsCommand,
  DescribeFirewallCommand,
  DescribeFirewallPolicyCommand,
  DescribeLoggingConfigurationCommand,
} from '@aws-sdk/client-network-firewall';
import { DescribeVpcsCommand, DescribeNetworkInterfacesCommand } from '@aws-sdk/client-ec2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const COMPLIANT_STATELESS_ACTIONS = ['aws:drop', 'aws:forward_to_sfe'];

interface FirewallInfo {
  arn: string;
  name: string;
  vpcId?: string;
  policyArn?: string;
  deletionProtection: boolean;
  subnetMappings: any[];
}

export class NetworkFirewallScanner extends BaseScanner {
  private networkfirewall: NetworkFirewallClient;

  constructor(client: AWSClient) {
    super(client, 'NetworkFirewall');
    this.networkfirewall = new NetworkFirewallClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting NetworkFirewall security scan...');

      const firewalls = await this.listFirewalls();
      const describedFirewalls: FirewallInfo[] = [];

      for (const firewall of firewalls) {
        logger.debug(`Scanning Network Firewall: ${firewall.name}`);
        try {
          const info = await this.describeFirewall(firewall.arn, firewall.name);
          describedFirewalls.push(info);
          findings.push(...await this.validateFirewall(info));
        } catch (error) {
          logger.debug(`Failed to scan Network Firewall ${firewall.name}`, { error: (error as Error).message });
        }
      }

      try {
        findings.push(...await this.checkFirewallInAllVpcs(describedFirewalls));
      } catch (error) {
        logger.debug('Failed to evaluate Network Firewall VPC coverage', { error: (error as Error).message });
      }

      logger.info(`NetworkFirewall scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('NetworkFirewall scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listFirewalls(): Promise<Array<{ arn: string; name: string }>> {
    const firewalls: Array<{ arn: string; name: string }> = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.networkfirewall.send(new ListFirewallsCommand({ NextToken: nextToken }));
      });
      for (const fw of result.Firewalls ?? []) {
        if (fw.FirewallArn) {
          firewalls.push({ arn: fw.FirewallArn, name: fw.FirewallName ?? fw.FirewallArn });
        }
      }
      nextToken = result.NextToken;
    } while (nextToken);
    return firewalls;
  }

  private async describeFirewall(arn: string, name: string): Promise<FirewallInfo> {
    const result = await retry(async () => {
      return await this.networkfirewall.send(new DescribeFirewallCommand({ FirewallArn: arn }));
    });
    const firewall: any = result.Firewall ?? {};
    return {
      arn,
      name: firewall.FirewallName ?? name,
      vpcId: firewall.VpcId,
      policyArn: firewall.FirewallPolicyArn,
      deletionProtection: firewall.DeleteProtection ?? false,
      subnetMappings: (firewall.SubnetMappings ?? []).filter((s: any) => s?.SubnetId),
    };
  }

  private async validateFirewall(firewall: FirewallInfo): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    // networkfirewall_deletion_protection
    if (!firewall.deletionProtection) {
      findings.push(this.emit(
        'networkfirewall_deletion_protection',
        { firewall: firewall.name, firewallArn: firewall.arn, deletionProtection: false },
        {
          message: `Network Firewall "${firewall.name}" does not have deletion protection enabled`,
        }
      ));
    }

    // networkfirewall_multi_az
    if (firewall.subnetMappings.length <= 1) {
      findings.push(this.emit(
        'networkfirewall_multi_az',
        { firewall: firewall.name, firewallArn: firewall.arn, subnetMappings: firewall.subnetMappings.map((s: any) => s.SubnetId) },
        {
          message: `Network Firewall "${firewall.name}" is not deployed across multiple Availability Zones`,
        }
      ));
    }

    // networkfirewall_logging_enabled
    try {
      const loggingResult = await retry(async () => {
        return await this.networkfirewall.send(new DescribeLoggingConfigurationCommand({ FirewallArn: firewall.arn }));
      });
      const destinationConfigs: any[] = loggingResult.LoggingConfiguration?.LogDestinationConfigs ?? [];
      const hasLogging = destinationConfigs.some((c: any) => c?.LogType || c?.LogDestination);
      if (!hasLogging) {
        findings.push(this.emit(
          'networkfirewall_logging_enabled',
          { firewall: firewall.name, firewallArn: firewall.arn, logDestinationConfigs: destinationConfigs.length },
          {
            message: `Network Firewall "${firewall.name}" does not have logging enabled`,
          }
        ));
      }
    } catch (error) {
      logger.debug(`Failed to describe logging configuration for firewall ${firewall.name}`, { error: (error as Error).message });
    }

    // Firewall policy checks
    if (firewall.policyArn) {
      try {
        const policyResult = await retry(async () => {
          return await this.networkfirewall.send(new DescribeFirewallPolicyCommand({ FirewallPolicyArn: firewall.policyArn }));
        });
        const policy: any = policyResult.FirewallPolicy ?? {};
        const statelessDefaultActions: string[] = policy.StatelessDefaultActions ?? [];
        const statelessFragmentDefaultActions: string[] = policy.StatelessFragmentDefaultActions ?? [];
        const statelessRuleGroups: any[] = policy.StatelessRuleGroupReferences ?? [];
        const statefulRuleGroups: any[] = policy.StatefulRuleGroupReferences ?? [];

        // networkfirewall_policy_default_action_full_packets
        if (!statelessDefaultActions.some((a) => COMPLIANT_STATELESS_ACTIONS.includes(a))) {
          findings.push(this.emit(
            'networkfirewall_policy_default_action_full_packets',
            { firewall: firewall.name, firewallArn: firewall.arn, policyArn: firewall.policyArn, statelessDefaultActions },
            {
              message: `Network Firewall "${firewall.name}" policy does not drop or forward full packets by default`,
            }
          ));
        }

        // networkfirewall_policy_default_action_fragmented_packets
        if (!statelessFragmentDefaultActions.some((a) => COMPLIANT_STATELESS_ACTIONS.includes(a))) {
          findings.push(this.emit(
            'networkfirewall_policy_default_action_fragmented_packets',
            { firewall: firewall.name, firewallArn: firewall.arn, policyArn: firewall.policyArn, statelessFragmentDefaultActions },
            {
              message: `Network Firewall "${firewall.name}" policy does not drop or forward fragmented packets by default`,
            }
          ));
        }

        // networkfirewall_policy_rule_group_associated
        if (statelessRuleGroups.length === 0 && statefulRuleGroups.length === 0) {
          findings.push(this.emit(
            'networkfirewall_policy_rule_group_associated',
            { firewall: firewall.name, firewallArn: firewall.arn, policyArn: firewall.policyArn, statelessRuleGroups: 0, statefulRuleGroups: 0 },
            {
              message: `Network Firewall "${firewall.name}" policy does not have any rule groups associated`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to describe firewall policy for firewall ${firewall.name}`, { error: (error as Error).message });
      }
    }

    return findings;
  }

  // networkfirewall_in_all_vpc: every in-use VPC (with ENIs) should have a Network Firewall
  private async checkFirewallInAllVpcs(firewalls: FirewallInfo[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const protectedVpcIds = new Set(firewalls.map((f) => f.vpcId).filter(Boolean));

    const vpcs: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.client.ec2.send(new DescribeVpcsCommand({ NextToken: nextToken }));
      });
      vpcs.push(...(result.Vpcs ?? []));
      nextToken = result.NextToken;
    } while (nextToken);

    for (const vpc of vpcs) {
      if (!vpc.VpcId) continue;
      if (protectedVpcIds.has(vpc.VpcId)) continue;
      try {
        // Only flag in-use VPCs (Prowler: VPCs with at least one network interface)
        const eniResult = await retry(async () => {
          return await this.client.ec2.send(new DescribeNetworkInterfacesCommand({
            Filters: [{ Name: 'vpc-id', Values: [vpc.VpcId] }],
            MaxResults: 5,
          }));
        });
        const inUse = (eniResult.NetworkInterfaces ?? []).length > 0;
        if (inUse) {
          findings.push(this.emit(
            'networkfirewall_in_all_vpc',
            { vpcId: vpc.VpcId, isDefault: vpc.IsDefault ?? false, networkFirewall: false },
            {
              message: `VPC "${vpc.VpcId}" is in use but does not have Network Firewall enabled`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to evaluate Network Firewall coverage for VPC ${vpc.VpcId}`, { error: (error as Error).message });
      }
    }

    return findings;
  }
}

export default NetworkFirewallScanner;
