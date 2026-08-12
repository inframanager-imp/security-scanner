// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  DescribeSecurityGroupsCommand,
  DescribeVpcsCommand,
  DescribeVpcPeeringConnectionsCommand,
  DescribeRouteTablesCommand,
  GetEbsEncryptionByDefaultCommand,
  DescribeRegionsCommand,
  DescribeSubnetsCommand,
  DescribeNetworkInterfacesCommand,
  DescribeVpcEndpointsCommand,
  DescribeVpcEndpointServicesCommand,
  DescribeVpcEndpointServicePermissionsCommand,
  DescribeVpnConnectionsCommand,
  EC2Client
} from '@aws-sdk/client-ec2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

/** Condition keys that scope a statement to an account/org (simplified port of Prowler's is_condition_block_restrictive). */
const RESTRICTIVE_ACCOUNT_CONDITION_KEYS = new Set([
  'aws:sourceaccount',
  'aws:sourceowner',
  'aws:sourcearn',
  'aws:principalaccount',
  'aws:principalarn',
  'aws:principalorgid',
  'aws:principalorgpaths',
  'aws:resourceaccount',
]);

/** Condition keys that restrict the network path rather than an account; any non-wildcard value counts as restrictive. */
const RESTRICTIVE_NETWORK_CONDITION_KEYS = new Set([
  'aws:sourcevpc',
  'aws:sourcevpce',
  'aws:sourceip',
  'aws:vpcsourceip',
]);

function toArray(value: any): any[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function nameTag(tags: any): string {
  for (const tag of toArray(tags)) {
    if (tag?.Key === 'Name' && tag?.Value) return String(tag.Value);
  }
  return '';
}

/** Extract the 12-digit account ID from a principal that may be an ARN, a bare account ID, or "*". */
function principalAccountId(principal: string): string {
  if (principal === '*') return '*';
  if (/^[0-9]{12}$/.test(principal)) return principal;
  const parts = principal.split(':');
  return parts.length > 4 ? parts[4] : '';
}

/** True when the condition block restricts access to one of the trusted accounts (or a specific network path). */
function conditionRestrictsToAccounts(condition: any, trustedAccounts: string[]): boolean {
  if (!condition || typeof condition !== 'object') return false;
  for (const operatorBlock of Object.values(condition)) {
    if (!operatorBlock || typeof operatorBlock !== 'object') continue;
    for (const [key, raw] of Object.entries(operatorBlock as Record<string, any>)) {
      const lowerKey = key.toLowerCase();
      const values = toArray(raw).map((v) => String(v));
      if (values.length === 0) continue;
      if (RESTRICTIVE_NETWORK_CONDITION_KEYS.has(lowerKey)) {
        if (values.some((v) => !v.includes('*'))) return true;
        continue;
      }
      if (!RESTRICTIVE_ACCOUNT_CONDITION_KEYS.has(lowerKey)) continue;
      if (trustedAccounts.some((account) => values.some((v) => v.includes(account)))) return true;
    }
  }
  return false;
}

/**
 * Port of Prowler's vpc_endpoint_connections_trust_boundaries statement walk:
 * a policy fails when any Allow statement grants access to a wildcard or
 * non-trusted AWS principal without a condition restricting it to a trusted
 * account.
 */
function endpointPolicyAllowsUntrusted(policy: any, trustedAccounts: string[]): boolean {
  for (const statement of toArray(policy?.Statement)) {
    if (!statement || typeof statement !== 'object' || statement.Effect !== 'Allow') continue;
    const principal = statement.Principal;
    let principals: string[] = [];
    if (principal === '*') {
      principals = ['*'];
    } else if (principal && typeof principal === 'object') {
      // Non-AWS principals (Service, Federated) are not evaluated, matching Prowler.
      principals = toArray(principal.AWS).map((p: any) => String(p));
    }
    for (const entry of principals) {
      const accountId = principalAccountId(entry);
      let trusted = accountId !== '*' && trustedAccounts.includes(accountId);
      // When a Condition is present it overrides the principal verdict (Prowler semantics).
      if (statement.Condition) trusted = conditionRestrictsToAccounts(statement.Condition, trustedAccounts);
      if (!trusted) return true;
    }
  }
  return false;
}

export class VPCScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'VPC');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting VPC security scan...');

      const defaultSgFindings = await this.checkDefaultSecurityGroups();
      findings.push(...defaultSgFindings);

      const peeringFindings = await this.checkVpcPeeringRoutes();
      findings.push(...peeringFindings);

      const ebsFindings = await this.checkEbsDefaultEncryption();
      findings.push(...ebsFindings);

      const defaultVpcFindings = await this.checkDefaultVpc();
      findings.push(...defaultVpcFindings);

      const parityFindings = await this.runProwlerParityChecks();
      findings.push(...parityFindings);

      logger.info(`VPC scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('VPC scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async checkDefaultVpc(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const result = await retry(async () => {
        const cmd = new DescribeVpcsCommand({
          Filters: [{ Name: 'is-default', Values: ['true'] }],
        });
        return await this.client.ec2.send(cmd);
      });

      for (const vpc of result.Vpcs ?? []) {
        findings.push(this.emit(
          'vpc_default_vpc_exists',
          { resourceId: `${vpc.VpcId}::default-vpc`, vpcId: vpc.VpcId, cidrBlock: vpc.CidrBlock },
          {
            message: `Default VPC "${vpc.VpcId}" exists in this region. The default VPC ships with an internet-route, default security group, and default ACL — ` +
              `resources accidentally launched into it inherit those permissive defaults.`,
            remediation: `Delete the default VPC if unused, or replace it with a custom VPC: aws ec2 delete-vpc --vpc-id ${vpc.VpcId}. Always launch workloads into a custom VPC.`,
          }
        ));
      }
    } catch (error) {
      logger.error('Failed to check default VPC', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkDefaultSecurityGroups(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new DescribeSecurityGroupsCommand({
          Filters: [{ Name: 'group-name', Values: ['default'] }]
        });
        return await this.client.ec2.send(cmd);
      });

      for (const sg of result.SecurityGroups || []) {
        const sgId = sg.GroupId || 'Unknown';
        const vpcId = sg.VpcId || 'Unknown';
        const inboundRules = (sg.IpPermissions || []).length;
        const outboundRules = (sg.IpPermissionsEgress || []).length;

        // Outbound default is a single "allow all" rule - check for traffic beyond that
        const hasProblematicOutbound = (sg.IpPermissionsEgress || []).some(rule => {
          const ipRanges = rule.IpRanges || [];
          const ipv6Ranges = rule.Ipv6Ranges || [];
          // Flag if there's anything other than the standard allow-all outbound
          const isAllowAllIpv4 =
            rule.IpProtocol === '-1' &&
            ipRanges.some(r => r.CidrIp === '0.0.0.0/0') &&
            ipv6Ranges.length === 0;
          const isAllowAllIpv6 =
            rule.IpProtocol === '-1' &&
            ipv6Ranges.some(r => r.CidrIpv6 === '::/0') &&
            ipRanges.length === 0;
          return !isAllowAllIpv4 && !isAllowAllIpv6;
        });

        if (inboundRules > 0 || hasProblematicOutbound) {
          findings.push(this.emit(
            'ec2_securitygroup_default_restrict_traffic',
            { sgId, vpcId, inboundRules, outboundRules },
            {
              message: `Default security group "${sgId}" in VPC "${vpcId}" has inbound or non-default outbound rules. Resources should not use the default security group, and it should have no rules.`,
            }
          ));
        }
      }
    } catch (error) {
      logger.error('Failed to check default security groups', { error: (error as Error).message });
    }

    return findings;
  }

  private async checkVpcPeeringRoutes(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const peeringResult = await retry(async () => {
        const cmd = new DescribeVpcPeeringConnectionsCommand({});
        return await this.client.ec2.send(cmd);
      });

      const peeringConnections = peeringResult.VpcPeeringConnections || [];
      if (peeringConnections.length === 0) {
        return findings;
      }

      const routeTablesResult = await retry(async () => {
        const cmd = new DescribeRouteTablesCommand({});
        return await this.client.ec2.send(cmd);
      });

      for (const routeTable of routeTablesResult.RouteTables || []) {
        const routeTableId = routeTable.RouteTableId || 'Unknown';

        for (const route of routeTable.Routes || []) {
          if (!route.VpcPeeringConnectionId) continue;

          const destinationCidr =
            route.DestinationCidrBlock || route.DestinationIpv6CidrBlock || '';

          const isOverlyBroad =
            destinationCidr === '0.0.0.0/0' ||
            destinationCidr === '::/0' ||
            destinationCidr.endsWith('/0');

          if (isOverlyBroad) {
            findings.push(this.emit(
              'vpc_peering_routing_tables_with_least_privilege',
              {
                peeringConnectionId: route.VpcPeeringConnectionId,
                routeTableId,
                destinationCidr
              },
              {
                message: `Route table "${routeTableId}" has an overly broad route (${destinationCidr}) pointing to VPC peering connection "${route.VpcPeeringConnectionId}". This violates least-privilege network access.`,
              }
            ));
          }
        }
      }
    } catch (error) {
      logger.error('Failed to check VPC peering routes', { error: (error as Error).message });
    }

    return findings;
  }

  /** Prowler-parity checks added for the native TS port (state gathered once, shared across checks). */
  private async runProwlerParityChecks(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    let accountId = '';
    try {
      accountId = await this.client.getAccountId();
    } catch (error) {
      logger.debug('VPC: unable to resolve account ID', { error: (error as Error).message });
    }
    const trustedAccounts = accountId ? [accountId] : [];

    try {
      const vpcs = await this.collectPages((t) => new DescribeVpcsCommand({ NextToken: t }), 'Vpcs');
      const subnets = await this.collectPages((t) => new DescribeSubnetsCommand({ NextToken: t }), 'Subnets');
      const routeTables = await this.collectPages((t) => new DescribeRouteTablesCommand({ NextToken: t }), 'RouteTables');
      const networkInterfaces = await this.collectPages(
        (t) => new DescribeNetworkInterfacesCommand({ NextToken: t }),
        'NetworkInterfaces'
      );
      const endpoints = await this.collectPages((t) => new DescribeVpcEndpointsCommand({ NextToken: t }), 'VpcEndpoints');

      // Prowler only evaluates VPCs/subnets that are in use (have at least one ENI).
      const inUseVpcIds = new Set<string>();
      const inUseSubnetIds = new Set<string>();
      for (const eni of networkInterfaces) {
        if (eni.VpcId) inUseVpcIds.add(eni.VpcId);
        if (eni.SubnetId) inUseSubnetIds.add(eni.SubnetId);
      }

      findings.push(...this.checkSubnetTopology(vpcs, subnets, routeTables, inUseVpcIds, inUseSubnetIds));
      findings.push(...this.checkVpcEndpoints(vpcs, endpoints, inUseVpcIds, trustedAccounts));
    } catch (error) {
      logger.error('Failed to run VPC topology checks', { error: (error as Error).message });
    }

    try {
      findings.push(...(await this.checkEndpointServicePermissions(accountId, trustedAccounts)));
    } catch (error) {
      logger.error('Failed to check VPC endpoint service permissions', { error: (error as Error).message });
    }

    try {
      findings.push(...(await this.checkVpnTunnels()));
    } catch (error) {
      logger.error('Failed to check VPN connection tunnels', { error: (error as Error).message });
    }

    try {
      findings.push(...(await this.checkVpcDifferentRegions(accountId)));
    } catch (error) {
      logger.error('Failed to check VPC region distribution', { error: (error as Error).message });
    }

    return findings;
  }

  /** Paginate an EC2 Describe* command, concatenating pages of `resultKey`. */
  private async collectPages(makeCommand: (nextToken?: string) => any, resultKey: string): Promise<any[]> {
    const items: any[] = [];
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.client.ec2.send(makeCommand(nextToken));
      });
      items.push(...(result[resultKey] ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return items;
  }

  // vpc_subnet_different_az / vpc_subnet_separate_private_public / vpc_subnet_no_public_ip_by_default
  private checkSubnetTopology(
    vpcs: any[],
    subnets: any[],
    routeTables: any[],
    inUseVpcIds: Set<string>,
    inUseSubnetIds: Set<string>
  ): ScanningResult[] {
    const findings: ScanningResult[] = [];

    // Route tables explicitly associated with a subnet; subnets without one use the VPC's main route table.
    const routeTablesBySubnet = new Map<string, any[]>();
    const mainRouteTableByVpc = new Map<string, any>();
    for (const routeTable of routeTables) {
      for (const association of routeTable.Associations ?? []) {
        if (association.SubnetId) {
          const list = routeTablesBySubnet.get(association.SubnetId) ?? [];
          list.push(routeTable);
          routeTablesBySubnet.set(association.SubnetId, list);
        }
        if (association.Main && routeTable.VpcId) {
          mainRouteTableByVpc.set(routeTable.VpcId, routeTable);
        }
      }
    }

    // A subnet is public when its effective route table has a 0.0.0.0/0 route to an internet
    // gateway (igw-*; the egress-only eigw-* variant does not make the subnet reachable).
    const subnetIsPublic = (subnet: any): boolean => {
      let tables = routeTablesBySubnet.get(subnet.SubnetId) ?? [];
      if (tables.length === 0 && mainRouteTableByVpc.has(subnet.VpcId)) {
        tables = [mainRouteTableByVpc.get(subnet.VpcId)];
      }
      return tables.some((routeTable: any) =>
        (routeTable.Routes ?? []).some(
          (route: any) =>
            typeof route.GatewayId === 'string' &&
            route.GatewayId.startsWith('igw-') &&
            route.DestinationCidrBlock === '0.0.0.0/0'
        )
      );
    };

    const subnetsByVpc = new Map<string, any[]>();
    for (const subnet of subnets) {
      if (!subnet.VpcId) continue;
      const list = subnetsByVpc.get(subnet.VpcId) ?? [];
      list.push(subnet);
      subnetsByVpc.set(subnet.VpcId, list);
    }

    for (const vpc of vpcs) {
      const vpcId: string = vpc.VpcId ?? '';
      if (!vpcId || !inUseVpcIds.has(vpcId)) continue;
      const vpcLabel = nameTag(vpc.Tags) || vpcId;
      const vpcSubnets = subnetsByVpc.get(vpcId) ?? [];

      // vpc_subnet_different_az
      const availabilityZones = new Set<string>(vpcSubnets.map((s: any) => String(s.AvailabilityZone ?? '')));
      if (vpcSubnets.length === 0) {
        findings.push(this.emit(
          'vpc_subnet_different_az',
          { resourceId: `${vpcId}::subnet-az`, vpcId, subnetCount: 0 },
          {
            message: `VPC "${vpcLabel}" has no subnets.`,
            remediation: `Create subnets in at least two Availability Zones in VPC ${vpcId}`,
          }
        ));
      } else if (availabilityZones.size === 1) {
        const az = [...availabilityZones][0];
        findings.push(this.emit(
          'vpc_subnet_different_az',
          { resourceId: `${vpcId}::subnet-az`, vpcId, availabilityZone: az, subnetCount: vpcSubnets.length },
          {
            message: `VPC "${vpcLabel}" has subnets only in availability zone ${az}.`,
            remediation: `Create at least one subnet in a second Availability Zone in VPC ${vpcId} and distribute workloads across zones`,
          }
        ));
      }

      // vpc_subnet_separate_private_public
      const hasPublic = vpcSubnets.some((s: any) => subnetIsPublic(s));
      const hasPrivate = vpcSubnets.some((s: any) => !subnetIsPublic(s));
      if (vpcSubnets.length === 0) {
        findings.push(this.emit(
          'vpc_subnet_separate_private_public',
          { resourceId: `${vpcId}::subnet-tiers`, vpcId, subnetCount: 0 },
          {
            message: `VPC "${vpcLabel}" has no subnets.`,
            remediation: `Create a public and a private subnet in VPC ${vpcId} to establish network segmentation`,
          }
        ));
      } else if (!(hasPublic && hasPrivate)) {
        const tier = hasPublic ? 'public' : 'private';
        findings.push(this.emit(
          'vpc_subnet_separate_private_public',
          { resourceId: `${vpcId}::subnet-tiers`, vpcId, hasPublic, hasPrivate },
          {
            message: `VPC "${vpcLabel}" has only ${tier} subnets.`,
            remediation: hasPublic
              ? `Add a private subnet (no internet gateway route) to VPC ${vpcId} and move internal workloads into it`
              : `Add a public subnet (0.0.0.0/0 route to an internet gateway) to VPC ${vpcId} for controlled internet-facing resources and egress`,
          }
        ));
      }
    }

    // vpc_subnet_no_public_ip_by_default
    for (const subnet of subnets) {
      const subnetId: string = subnet.SubnetId ?? '';
      if (!subnetId || !inUseSubnetIds.has(subnetId)) continue;
      if (!subnet.MapPublicIpOnLaunch) continue;
      const subnetLabel = nameTag(subnet.Tags) || subnetId;
      findings.push(this.emit(
        'vpc_subnet_no_public_ip_by_default',
        { subnetId, vpcId: subnet.VpcId, mapPublicIpOnLaunch: true },
        {
          message: `VPC subnet "${subnetLabel}" assigns public IP addresses by default (MapPublicIpOnLaunch=true).`,
          remediation: `Disable auto-assign public IPv4 on the subnet: aws ec2 modify-subnet-attribute --subnet-id ${subnetId} --no-map-public-ip-on-launch`,
        }
      ));
    }

    return findings;
  }

  // vpc_endpoint_for_ec2_enabled / vpc_endpoint_multi_az_enabled / vpc_endpoint_connections_trust_boundaries
  private checkVpcEndpoints(
    vpcs: any[],
    endpoints: any[],
    inUseVpcIds: Set<string>,
    trustedAccounts: string[]
  ): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const vpcIds = new Set<string>(vpcs.map((v: any) => String(v.VpcId ?? '')));

    // vpc_endpoint_for_ec2_enabled
    for (const vpc of vpcs) {
      const vpcId: string = vpc.VpcId ?? '';
      if (!vpcId || !inUseVpcIds.has(vpcId)) continue;
      const hasEc2Endpoint = endpoints.some(
        (endpoint: any) => endpoint.VpcId === vpcId && String(endpoint.ServiceName ?? '').includes('ec2')
      );
      if (!hasEc2Endpoint) {
        const vpcLabel = nameTag(vpc.Tags) || vpcId;
        findings.push(this.emit(
          'vpc_endpoint_for_ec2_enabled',
          { resourceId: `${vpcId}::ec2-endpoint`, vpcId },
          {
            message: `VPC "${vpcLabel}" has no EC2 endpoint.`,
            remediation: `Create an interface VPC endpoint for the EC2 API: aws ec2 create-vpc-endpoint --vpc-id ${vpcId} --service-name com.amazonaws.${this.client.getRegion()}.ec2 --vpc-endpoint-type Interface`,
          }
        ));
      }
    }

    for (const endpoint of endpoints) {
      const endpointId: string = endpoint.VpcEndpointId ?? '';
      const vpcId: string = endpoint.VpcId ?? '';
      const serviceName: string = endpoint.ServiceName ?? '';
      if (!endpointId) continue;

      // vpc_endpoint_multi_az_enabled — interface endpoints must span more than one subnet/AZ
      if (endpoint.VpcEndpointType === 'Interface' && vpcIds.has(vpcId)) {
        const subnetIds: string[] = endpoint.SubnetIds ?? [];
        if (subnetIds.length <= 1) {
          findings.push(this.emit(
            'vpc_endpoint_multi_az_enabled',
            { endpointId, vpcId, serviceName, subnetIds },
            {
              message: `VPC endpoint "${endpointId}" in VPC "${vpcId}" does not have subnets in different AZs.`,
              remediation: `Add a subnet in a second Availability Zone to endpoint ${endpointId}: aws ec2 modify-vpc-endpoint --vpc-endpoint-id ${endpointId} --add-subnet-ids <subnet-id>`,
            }
          ));
        }
      }

      // vpc_endpoint_connections_trust_boundaries — skip com.amazonaws.vpce.* endpoints (policy not editable)
      if (endpoint.PolicyDocument && !serviceName.includes('com.amazonaws.vpce.')) {
        let policy: any = null;
        try {
          policy = JSON.parse(endpoint.PolicyDocument);
        } catch (error) {
          logger.debug(`Failed to parse policy for VPC endpoint ${endpointId}`, { error: (error as Error).message });
        }
        if (policy && endpointPolicyAllowsUntrusted(policy, trustedAccounts)) {
          findings.push(this.emit(
            'vpc_endpoint_connections_trust_boundaries',
            { endpointId, vpcId, serviceName },
            {
              message: `VPC endpoint "${endpointId}" in VPC "${vpcId}" can be accessed from non-trusted accounts.`,
              remediation: `Restrict the policy of endpoint ${endpointId} with a StringEquals condition on aws:PrincipalAccount listing only trusted account IDs`,
            }
          ));
        }
      }
    }

    return findings;
  }

  // vpc_endpoint_services_allowed_principals_trust_boundaries
  private async checkEndpointServicePermissions(accountId: string, trustedAccounts: string[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    // The API returns every service available in the region; only services owned by this account can be audited.
    const services = (await this.collectPages(
      (t) => new DescribeVpcEndpointServicesCommand({ NextToken: t }),
      'ServiceDetails'
    )).filter((service: any) => accountId && service.Owner === accountId);

    for (const service of services) {
      const serviceId: string = service.ServiceId ?? '';
      if (!serviceId) continue;
      try {
        const principals: string[] = [];
        let nextToken: string | undefined;
        do {
          const result: any = await retry(async () => {
            return await this.client.ec2.send(
              new DescribeVpcEndpointServicePermissionsCommand({ ServiceId: serviceId, NextToken: nextToken })
            );
          });
          principals.push(...(result.AllowedPrincipals ?? []).map((p: any) => String(p.Principal ?? '')));
          nextToken = result.NextToken;
        } while (nextToken);

        const untrusted = principals.filter((principal) => {
          if (!principal) return false;
          const principalAccount = principalAccountId(principal);
          return principalAccount === '*' || !trustedAccounts.includes(principalAccount);
        });

        if (untrusted.length > 0) {
          const hasWildcard = untrusted.some((p) => principalAccountId(p) === '*');
          findings.push(this.emit(
            'vpc_endpoint_services_allowed_principals_trust_boundaries',
            { serviceId, serviceName: service.ServiceName, untrustedPrincipals: untrusted },
            {
              message: hasWildcard
                ? `Wildcard principal found in VPC endpoint service "${serviceId}".`
                : `Found untrusted account(s) ${untrusted.map((p) => principalAccountId(p)).join(', ')} in VPC endpoint service "${serviceId}".`,
              remediation: `Remove wildcard and untrusted entries from the allowed principals of endpoint service ${serviceId}, keeping only vetted account IDs or role ARNs`,
            }
          ));
        }
      } catch (error) {
        logger.debug(`Failed to check permissions for VPC endpoint service ${serviceId}`, { error: (error as Error).message });
      }
    }

    return findings;
  }

  // vpc_vpn_connection_tunnels_up
  private async checkVpnTunnels(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const result = await retry(async () => {
      return await this.client.ec2.send(new DescribeVpnConnectionsCommand({}));
    });

    for (const vpnConnection of result.VpnConnections ?? []) {
      const vpnId = vpnConnection.VpnConnectionId ?? 'Unknown';
      const tunnels: any[] = vpnConnection.VgwTelemetry ?? [];
      const downTunnels = tunnels.filter((tunnel: any) => tunnel.Status !== 'UP');
      if (tunnels.length < 2 || downTunnels.length > 0) {
        findings.push(this.emit(
          'vpc_vpn_connection_tunnels_up',
          {
            vpnConnectionId: vpnId,
            tunnelStatuses: tunnels.map((t: any) => ({ outsideIpAddress: t.OutsideIpAddress, status: t.Status })),
          },
          {
            message: `VPN connection "${vpnId}" has at least one tunnel DOWN.`,
            remediation: `Configure both tunnels of VPN connection ${vpnId} on the customer gateway device and verify both report Status UP`,
          }
        ));
      }
    }

    return findings;
  }

  // vpc_different_regions — account-level: non-default VPCs should span more than one region
  private async checkVpcDifferentRegions(accountId: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const regionsResult = await retry(async () => {
      return await this.client.ec2.send(new DescribeRegionsCommand({ AllRegions: false }));
    });
    const regionNames = (regionsResult.Regions ?? [])
      .map((r: any) => String(r.RegionName ?? ''))
      .filter((r: string) => r.length > 0);

    let totalVpcs = 0;
    const regionsWithNonDefaultVpcs = new Set<string>();
    for (const regionName of regionNames) {
      try {
        const regionalEc2 = new EC2Client({ ...this.client.getClientConfig(), region: regionName });
        let nextToken: string | undefined;
        do {
          const result: any = await retry(async () => {
            return await regionalEc2.send(new DescribeVpcsCommand({ NextToken: nextToken }));
          });
          for (const vpc of result.Vpcs ?? []) {
            totalVpcs++;
            if (!vpc.IsDefault) regionsWithNonDefaultVpcs.add(regionName);
          }
          nextToken = result.NextToken;
        } while (nextToken);
      } catch (error) {
        logger.debug(`Failed to describe VPCs in region ${regionName}`, { error: (error as Error).message });
      }
    }

    if (totalVpcs > 0 && regionsWithNonDefaultVpcs.size <= 1) {
      const regionList = [...regionsWithNonDefaultVpcs].sort();
      findings.push(this.emit(
        'vpc_different_regions',
        // Account-scoped, region-independent evidence so the same finding dedupes across scan regions.
        { resourceId: `${accountId || 'account'}::vpc-regions`, regionsWithNonDefaultVpcs: regionList },
        {
          message: regionList.length === 1
            ? `Non-default VPCs exist only in region ${regionList[0]}; a regional outage would take down the entire custom network topology.`
            : 'No non-default VPCs exist in any region; only default VPCs are present.',
          remediation: 'Create a non-default VPC in at least one additional region: aws ec2 create-vpc --region <other-region> --cidr-block <cidr>',
        }
      ));
    }

    return findings;
  }

  private async checkEbsDefaultEncryption(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new GetEbsEncryptionByDefaultCommand({});
        return await this.client.ec2.send(cmd);
      });

      if (!result.EbsEncryptionByDefault) {
        findings.push(this.emit(
          'vpc_ebs_default_encryption_disabled',
          { ebsEncryptionEnabled: false },
          {
            message: 'EBS default encryption is not enabled. New EBS volumes will not be automatically encrypted at rest.',
          }
        ));
      }
    } catch (error) {
      logger.error('Failed to check EBS default encryption', { error: (error as Error).message });
    }

    return findings;
  }
}

export default VPCScanner;
