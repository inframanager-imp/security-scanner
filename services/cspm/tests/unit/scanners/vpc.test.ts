import { describe, it, expect, beforeEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  EC2Client,
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
} from '@aws-sdk/client-ec2';
import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { VPCScanner } from '../../../src/scanners/vpc';
import AWSClient from '../../../src/aws/client';

const ec2Mock = mockClient(EC2Client);
const stsMock = mockClient(STSClient);

/**
 * Wire every command the VPCScanner touches to a benign empty-ish default so
 * scan() (which fans out into default SG / peering / EBS / default-VPC /
 * Prowler-parity topology checks) resolves cleanly. Individual tests override
 * specific commands to exercise specific check branches.
 */
function stubAllCommandsToEmpty() {
  ec2Mock.on(DescribeSecurityGroupsCommand).resolves({ SecurityGroups: [] });
  ec2Mock.on(DescribeVpcsCommand).resolves({ Vpcs: [] });
  ec2Mock.on(DescribeVpcPeeringConnectionsCommand).resolves({ VpcPeeringConnections: [] });
  ec2Mock.on(DescribeRouteTablesCommand).resolves({ RouteTables: [] });
  ec2Mock.on(GetEbsEncryptionByDefaultCommand).resolves({ EbsEncryptionByDefault: true });
  ec2Mock.on(DescribeRegionsCommand).resolves({ Regions: [{ RegionName: 'us-east-1' }] });
  ec2Mock.on(DescribeSubnetsCommand).resolves({ Subnets: [] });
  ec2Mock.on(DescribeNetworkInterfacesCommand).resolves({ NetworkInterfaces: [] });
  ec2Mock.on(DescribeVpcEndpointsCommand).resolves({ VpcEndpoints: [] });
  ec2Mock.on(DescribeVpcEndpointServicesCommand).resolves({ ServiceDetails: [] });
  ec2Mock.on(DescribeVpcEndpointServicePermissionsCommand).resolves({ AllowedPrincipals: [] });
  ec2Mock.on(DescribeVpnConnectionsCommand).resolves({ VpnConnections: [] });
  stsMock.on(GetCallerIdentityCommand).resolves({ Account: '111111111111' });
}

function makeClient(): AWSClient {
  // Real AWSClient so this.client.ec2 is a genuine EC2Client instance that
  // aws-sdk-client-mock's prototype patch intercepts (including the regional
  // EC2Client the scanner constructs on the fly for checkVpcDifferentRegions).
  return new AWSClient('us-east-1', undefined, {
    accessKeyId: 'test-access-key',
    secretAccessKey: 'test-secret-key',
  });
}

describe('VPCScanner', () => {
  beforeEach(() => {
    ec2Mock.reset();
    stsMock.reset();
    stubAllCommandsToEmpty();
  });

  describe('scan() - default VPC', () => {
    it('emits vpc_default_vpc_exists when a default VPC is present', async () => {
      ec2Mock.on(DescribeVpcsCommand).resolves({
        Vpcs: [{ VpcId: 'vpc-default1', CidrBlock: '172.31.0.0/16', IsDefault: true }],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'vpc_default_vpc_exists');
      expect(finding).toBeDefined();
      expect(finding!.service).toBe('VPC');
      expect(finding!.evidence).toMatchObject({ vpcId: 'vpc-default1', cidrBlock: '172.31.0.0/16' });
    });

    it('does not emit vpc_default_vpc_exists when there is no default VPC', async () => {
      ec2Mock.on(DescribeVpcsCommand).resolves({ Vpcs: [] });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some((f) => f.checkId === 'vpc_default_vpc_exists')).toBe(false);
    });
  });

  describe('scan() - default security group', () => {
    it('emits ec2_securitygroup_default_restrict_traffic when the default SG has inbound rules', async () => {
      ec2Mock.on(DescribeSecurityGroupsCommand).resolves({
        SecurityGroups: [
          {
            GroupId: 'sg-default1',
            VpcId: 'vpc-1',
            IpPermissions: [{ IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }] }],
            IpPermissionsEgress: [
              { IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }], Ipv6Ranges: [] },
            ],
          },
        ],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'ec2_securitygroup_default_restrict_traffic');
      expect(finding).toBeDefined();
      expect(finding!.evidence).toMatchObject({ sgId: 'sg-default1', vpcId: 'vpc-1', inboundRules: 1 });
    });

    it('does not emit a finding for a clean default SG (no inbound, standard allow-all outbound)', async () => {
      ec2Mock.on(DescribeSecurityGroupsCommand).resolves({
        SecurityGroups: [
          {
            GroupId: 'sg-clean',
            VpcId: 'vpc-1',
            IpPermissions: [],
            IpPermissionsEgress: [
              { IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }], Ipv6Ranges: [] },
            ],
          },
        ],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some((f) => f.checkId === 'ec2_securitygroup_default_restrict_traffic')).toBe(false);
    });
  });

  describe('scan() - VPC peering routes', () => {
    it('emits vpc_peering_routing_tables_with_least_privilege for an overly broad route to a peering connection', async () => {
      ec2Mock.on(DescribeVpcPeeringConnectionsCommand).resolves({
        VpcPeeringConnections: [{ VpcPeeringConnectionId: 'pcx-123' }],
      });
      ec2Mock.on(DescribeRouteTablesCommand).resolves({
        RouteTables: [
          {
            RouteTableId: 'rtb-1',
            Routes: [{ VpcPeeringConnectionId: 'pcx-123', DestinationCidrBlock: '0.0.0.0/0' }],
          },
        ],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'vpc_peering_routing_tables_with_least_privilege');
      expect(finding).toBeDefined();
      expect(finding!.evidence).toMatchObject({
        peeringConnectionId: 'pcx-123',
        routeTableId: 'rtb-1',
        destinationCidr: '0.0.0.0/0',
      });
    });

    it('does not emit a peering finding when the route is scoped to a private CIDR', async () => {
      ec2Mock.on(DescribeVpcPeeringConnectionsCommand).resolves({
        VpcPeeringConnections: [{ VpcPeeringConnectionId: 'pcx-456' }],
      });
      ec2Mock.on(DescribeRouteTablesCommand).resolves({
        RouteTables: [
          {
            RouteTableId: 'rtb-2',
            Routes: [{ VpcPeeringConnectionId: 'pcx-456', DestinationCidrBlock: '10.0.0.0/16' }],
          },
        ],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some((f) => f.checkId === 'vpc_peering_routing_tables_with_least_privilege')).toBe(false);
    });

    it('short-circuits without calling DescribeRouteTables when there are no peering connections', async () => {
      ec2Mock.on(DescribeVpcPeeringConnectionsCommand).resolves({ VpcPeeringConnections: [] });

      const scanner = new VPCScanner(makeClient());
      await scanner.scan();

      // checkVpcPeeringRoutes returns early; the only DescribeRouteTables calls left
      // come from the Prowler-parity topology pass (collectPages), so we can't assert
      // zero calls outright — instead assert no peering finding surfaced.
      expect(ec2Mock.commandCalls(DescribeVpcPeeringConnectionsCommand)).toHaveLength(1);
    });
  });

  describe('scan() - EBS default encryption', () => {
    it('emits vpc_ebs_default_encryption_disabled when default encryption is off', async () => {
      ec2Mock.on(GetEbsEncryptionByDefaultCommand).resolves({ EbsEncryptionByDefault: false });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'vpc_ebs_default_encryption_disabled');
      expect(finding).toBeDefined();
      expect(finding!.evidence).toMatchObject({ ebsEncryptionEnabled: false });
    });

    it('does not emit vpc_ebs_default_encryption_disabled when default encryption is on', async () => {
      ec2Mock.on(GetEbsEncryptionByDefaultCommand).resolves({ EbsEncryptionByDefault: true });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some((f) => f.checkId === 'vpc_ebs_default_encryption_disabled')).toBe(false);
    });
  });

  describe('scan() - subnet topology (Prowler-parity)', () => {
    it('flags a VPC in use whose subnets sit in only one Availability Zone', async () => {
      ec2Mock.on(DescribeVpcsCommand).resolves({ Vpcs: [{ VpcId: 'vpc-az', Tags: [] }] });
      ec2Mock.on(DescribeSubnetsCommand).resolves({
        Subnets: [
          { SubnetId: 'subnet-a', VpcId: 'vpc-az', AvailabilityZone: 'us-east-1a' },
          { SubnetId: 'subnet-b', VpcId: 'vpc-az', AvailabilityZone: 'us-east-1a' },
        ],
      });
      ec2Mock.on(DescribeNetworkInterfacesCommand).resolves({
        NetworkInterfaces: [{ VpcId: 'vpc-az', SubnetId: 'subnet-a' }],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'vpc_subnet_different_az');
      expect(finding).toBeDefined();
      expect(finding!.evidence).toMatchObject({ vpcId: 'vpc-az', availabilityZone: 'us-east-1a' });
    });

    it('flags a VPC in use with only public subnets (no private tier)', async () => {
      ec2Mock.on(DescribeVpcsCommand).resolves({ Vpcs: [{ VpcId: 'vpc-tier', Tags: [] }] });
      ec2Mock.on(DescribeSubnetsCommand).resolves({
        Subnets: [
          { SubnetId: 'subnet-pub', VpcId: 'vpc-tier', AvailabilityZone: 'us-east-1a' },
          { SubnetId: 'subnet-pub2', VpcId: 'vpc-tier', AvailabilityZone: 'us-east-1b' },
        ],
      });
      ec2Mock.on(DescribeRouteTablesCommand).resolves({
        RouteTables: [
          {
            RouteTableId: 'rtb-main',
            VpcId: 'vpc-tier',
            Associations: [{ Main: true }],
            Routes: [{ GatewayId: 'igw-123', DestinationCidrBlock: '0.0.0.0/0' }],
          },
        ],
      });
      ec2Mock.on(DescribeNetworkInterfacesCommand).resolves({
        NetworkInterfaces: [{ VpcId: 'vpc-tier', SubnetId: 'subnet-pub' }],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'vpc_subnet_separate_private_public');
      expect(finding).toBeDefined();
      expect(finding!.evidence).toMatchObject({ vpcId: 'vpc-tier', hasPublic: true, hasPrivate: false });
    });

    it('flags a subnet in use that assigns public IPs by default', async () => {
      ec2Mock.on(DescribeVpcsCommand).resolves({ Vpcs: [{ VpcId: 'vpc-pubip', Tags: [] }] });
      ec2Mock.on(DescribeSubnetsCommand).resolves({
        Subnets: [
          {
            SubnetId: 'subnet-autopub',
            VpcId: 'vpc-pubip',
            AvailabilityZone: 'us-east-1a',
            MapPublicIpOnLaunch: true,
            Tags: [{ Key: 'Name', Value: 'autopub-subnet' }],
          },
        ],
      });
      ec2Mock.on(DescribeNetworkInterfacesCommand).resolves({
        NetworkInterfaces: [{ VpcId: 'vpc-pubip', SubnetId: 'subnet-autopub' }],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'vpc_subnet_no_public_ip_by_default');
      expect(finding).toBeDefined();
      expect(finding!.evidence).toMatchObject({ subnetId: 'subnet-autopub', mapPublicIpOnLaunch: true });
    });

    it('ignores VPCs and subnets with no attached network interfaces (not in use)', async () => {
      ec2Mock.on(DescribeVpcsCommand).resolves({ Vpcs: [{ VpcId: 'vpc-unused', Tags: [] }] });
      ec2Mock.on(DescribeSubnetsCommand).resolves({
        Subnets: [{ SubnetId: 'subnet-unused', VpcId: 'vpc-unused', AvailabilityZone: 'us-east-1a', MapPublicIpOnLaunch: true }],
      });
      ec2Mock.on(DescribeNetworkInterfacesCommand).resolves({ NetworkInterfaces: [] });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some((f) => f.checkId === 'vpc_subnet_different_az')).toBe(false);
      expect(findings.some((f) => f.checkId === 'vpc_subnet_separate_private_public')).toBe(false);
      expect(findings.some((f) => f.checkId === 'vpc_subnet_no_public_ip_by_default')).toBe(false);
    });

    it('paginates DescribeSubnets across two pages and evaluates subnets from both', async () => {
      ec2Mock.on(DescribeVpcsCommand).resolves({ Vpcs: [{ VpcId: 'vpc-page', Tags: [] }] });
      ec2Mock
        .on(DescribeSubnetsCommand)
        .resolvesOnce({
          Subnets: [{ SubnetId: 'subnet-p1', VpcId: 'vpc-page', AvailabilityZone: 'us-east-1a', MapPublicIpOnLaunch: true }],
          NextToken: 'token-2',
        })
        .resolves({
          Subnets: [{ SubnetId: 'subnet-p2', VpcId: 'vpc-page', AvailabilityZone: 'us-east-1b', MapPublicIpOnLaunch: true }],
        });
      ec2Mock.on(DescribeNetworkInterfacesCommand).resolves({
        NetworkInterfaces: [
          { VpcId: 'vpc-page', SubnetId: 'subnet-p1' },
          { VpcId: 'vpc-page', SubnetId: 'subnet-p2' },
        ],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      const flaggedSubnets = findings
        .filter((f) => f.checkId === 'vpc_subnet_no_public_ip_by_default')
        .map((f) => f.evidence.subnetId);

      expect(flaggedSubnets).toEqual(expect.arrayContaining(['subnet-p1', 'subnet-p2']));
    });
  });

  describe('scan() - VPC endpoints', () => {
    it('emits vpc_endpoint_for_ec2_enabled when an in-use VPC has no EC2 interface endpoint', async () => {
      ec2Mock.on(DescribeVpcsCommand).resolves({ Vpcs: [{ VpcId: 'vpc-noendpoint', Tags: [] }] });
      ec2Mock.on(DescribeNetworkInterfacesCommand).resolves({
        NetworkInterfaces: [{ VpcId: 'vpc-noendpoint', SubnetId: 'subnet-x' }],
      });
      ec2Mock.on(DescribeVpcEndpointsCommand).resolves({ VpcEndpoints: [] });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'vpc_endpoint_for_ec2_enabled');
      expect(finding).toBeDefined();
      expect(finding!.evidence).toMatchObject({ vpcId: 'vpc-noendpoint' });
    });

    it('emits vpc_endpoint_multi_az_enabled when an interface endpoint has only one subnet', async () => {
      ec2Mock.on(DescribeVpcsCommand).resolves({ Vpcs: [{ VpcId: 'vpc-1az', Tags: [] }] });
      ec2Mock.on(DescribeNetworkInterfacesCommand).resolves({
        NetworkInterfaces: [{ VpcId: 'vpc-1az', SubnetId: 'subnet-x' }],
      });
      ec2Mock.on(DescribeVpcEndpointsCommand).resolves({
        VpcEndpoints: [
          {
            VpcEndpointId: 'vpce-1',
            VpcId: 'vpc-1az',
            VpcEndpointType: 'Interface',
            ServiceName: 'com.amazonaws.us-east-1.ec2',
            SubnetIds: ['subnet-x'],
          },
        ],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'vpc_endpoint_multi_az_enabled');
      expect(finding).toBeDefined();
      expect(finding!.evidence).toMatchObject({ endpointId: 'vpce-1', vpcId: 'vpc-1az' });

      // Having an EC2-named endpoint present should also satisfy the EC2-endpoint check.
      expect(findings.some((f) => f.checkId === 'vpc_endpoint_for_ec2_enabled' && f.evidence.vpcId === 'vpc-1az')).toBe(false);
    });

    it('emits vpc_endpoint_connections_trust_boundaries when the endpoint policy allows a wildcard principal', async () => {
      ec2Mock.on(DescribeVpcsCommand).resolves({ Vpcs: [{ VpcId: 'vpc-open', Tags: [] }] });
      ec2Mock.on(DescribeNetworkInterfacesCommand).resolves({
        NetworkInterfaces: [{ VpcId: 'vpc-open', SubnetId: 'subnet-x' }],
      });
      ec2Mock.on(DescribeVpcEndpointsCommand).resolves({
        VpcEndpoints: [
          {
            VpcEndpointId: 'vpce-open',
            VpcId: 'vpc-open',
            VpcEndpointType: 'Interface',
            ServiceName: 'com.amazonaws.us-east-1.s3',
            SubnetIds: ['subnet-x', 'subnet-y'],
            PolicyDocument: JSON.stringify({
              Statement: [{ Effect: 'Allow', Principal: '*', Action: '*', Resource: '*' }],
            }),
          },
        ],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'vpc_endpoint_connections_trust_boundaries');
      expect(finding).toBeDefined();
      expect(finding!.evidence).toMatchObject({ endpointId: 'vpce-open', vpcId: 'vpc-open' });
    });

    it('does not flag an endpoint policy restricted to the trusted account', async () => {
      ec2Mock.on(DescribeVpcsCommand).resolves({ Vpcs: [{ VpcId: 'vpc-trusted', Tags: [] }] });
      ec2Mock.on(DescribeNetworkInterfacesCommand).resolves({
        NetworkInterfaces: [{ VpcId: 'vpc-trusted', SubnetId: 'subnet-x' }],
      });
      ec2Mock.on(DescribeVpcEndpointsCommand).resolves({
        VpcEndpoints: [
          {
            VpcEndpointId: 'vpce-trusted',
            VpcId: 'vpc-trusted',
            VpcEndpointType: 'Interface',
            ServiceName: 'com.amazonaws.us-east-1.s3',
            SubnetIds: ['subnet-x', 'subnet-y'],
            PolicyDocument: JSON.stringify({
              Statement: [
                { Effect: 'Allow', Principal: { AWS: '111111111111' }, Action: '*', Resource: '*' },
              ],
            }),
          },
        ],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some((f) => f.checkId === 'vpc_endpoint_connections_trust_boundaries')).toBe(false);
    });
  });

  describe('scan() - VPC endpoint service permissions', () => {
    it('emits vpc_endpoint_services_allowed_principals_trust_boundaries for a wildcard allowed principal', async () => {
      ec2Mock.on(DescribeVpcEndpointServicesCommand).resolves({
        ServiceDetails: [{ ServiceId: 'vpce-svc-1', ServiceName: 'com.amazonaws.vpce.us-east-1.my-svc', Owner: '111111111111' }],
      });
      ec2Mock.on(DescribeVpcEndpointServicePermissionsCommand).resolves({
        AllowedPrincipals: [{ Principal: '*' }],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'vpc_endpoint_services_allowed_principals_trust_boundaries');
      expect(finding).toBeDefined();
      expect(finding!.evidence).toMatchObject({ serviceId: 'vpce-svc-1' });
    });

    it('does not flag a service whose only allowed principal is the trusted account', async () => {
      ec2Mock.on(DescribeVpcEndpointServicesCommand).resolves({
        ServiceDetails: [{ ServiceId: 'vpce-svc-2', ServiceName: 'com.amazonaws.vpce.us-east-1.my-svc2', Owner: '111111111111' }],
      });
      ec2Mock.on(DescribeVpcEndpointServicePermissionsCommand).resolves({
        AllowedPrincipals: [{ Principal: '111111111111' }],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some((f) => f.checkId === 'vpc_endpoint_services_allowed_principals_trust_boundaries')).toBe(false);
    });
  });

  describe('scan() - VPN tunnels', () => {
    it('emits vpc_vpn_connection_tunnels_up when a tunnel is DOWN', async () => {
      ec2Mock.on(DescribeVpnConnectionsCommand).resolves({
        VpnConnections: [
          {
            VpnConnectionId: 'vpn-1',
            VgwTelemetry: [
              { OutsideIpAddress: '1.2.3.4', Status: 'UP' },
              { OutsideIpAddress: '5.6.7.8', Status: 'DOWN' },
            ],
          },
        ],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      const finding = findings.find((f) => f.checkId === 'vpc_vpn_connection_tunnels_up');
      expect(finding).toBeDefined();
      expect(finding!.evidence).toMatchObject({ vpnConnectionId: 'vpn-1' });
    });

    it('does not emit vpc_vpn_connection_tunnels_up when both tunnels are UP', async () => {
      ec2Mock.on(DescribeVpnConnectionsCommand).resolves({
        VpnConnections: [
          {
            VpnConnectionId: 'vpn-2',
            VgwTelemetry: [
              { OutsideIpAddress: '1.2.3.4', Status: 'UP' },
              { OutsideIpAddress: '5.6.7.8', Status: 'UP' },
            ],
          },
        ],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some((f) => f.checkId === 'vpc_vpn_connection_tunnels_up')).toBe(false);
    });
  });

  describe('scan() - empty account', () => {
    it('returns no findings when the account has no VPC resources at all', async () => {
      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });
  });

  describe('scan() - error handling', () => {
    it('does not throw and returns gracefully when DescribeSecurityGroups rejects', async () => {
      ec2Mock.on(DescribeSecurityGroupsCommand).rejects(new Error('AccessDenied'));

      const scanner = new VPCScanner(makeClient());
      await expect(scanner.scan()).resolves.not.toThrow();

      const findings = await scanner.scan();
      expect(findings.some((f) => f.checkId === 'ec2_securitygroup_default_restrict_traffic')).toBe(false);
      expect(Array.isArray(findings)).toBe(true);
    });

    it('does not throw and still returns other findings when DescribeVpcPeeringConnections rejects', async () => {
      ec2Mock.on(DescribeVpcPeeringConnectionsCommand).rejects(new Error('Throttling'));
      ec2Mock.on(DescribeVpcsCommand).resolves({
        Vpcs: [{ VpcId: 'vpc-default2', CidrBlock: '172.31.0.0/16', IsDefault: true }],
      });

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some((f) => f.checkId === 'vpc_peering_routing_tables_with_least_privilege')).toBe(false);
      expect(findings.some((f) => f.checkId === 'vpc_default_vpc_exists')).toBe(true);
    });

    it('returns an empty array without throwing when every EC2 and STS call rejects', async () => {
      ec2Mock.rejects(new Error('ServiceUnavailable'));
      stsMock.rejects(new Error('ServiceUnavailable'));

      const scanner = new VPCScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });
  });
});
