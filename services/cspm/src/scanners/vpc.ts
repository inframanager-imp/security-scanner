import {
  DescribeSecurityGroupsCommand,
  DescribeVpcsCommand,
  DescribeVpcPeeringConnectionsCommand,
  DescribeRouteTablesCommand,
  GetEbsEncryptionByDefaultCommand
} from '@aws-sdk/client-ec2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

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
        findings.push(this.createFinding(
          'Default VPC Exists',
          `Default VPC "${vpc.VpcId}" exists in this region. The default VPC ships with an internet-route, default security group, and default ACL — ` +
          `resources accidentally launched into it inherit those permissive defaults.`,
          'LOW',
          { resourceId: `${vpc.VpcId}::default-vpc`, vpcId: vpc.VpcId, cidrBlock: vpc.CidrBlock },
          `Delete the default VPC if unused, or replace it with a custom VPC: aws ec2 delete-vpc --vpc-id ${vpc.VpcId}. Always launch workloads into a custom VPC.`,
          ['vpc', 'default-vpc', 'cis-5.1'],
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
          findings.push(this.createFinding(
            'Default Security Group Not Restricted',
            `Default security group "${sgId}" in VPC "${vpcId}" has inbound or non-default outbound rules. Resources should not use the default security group, and it should have no rules.`,
            'MEDIUM',
            { sgId, vpcId, inboundRules, outboundRules },
            'Remove all inbound and outbound rules from the default security group in each VPC',
            ['vpc', 'security-group', 'cis-5.3']
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
            findings.push(this.createFinding(
              'VPC Peering Route Not Least Access',
              `Route table "${routeTableId}" has an overly broad route (${destinationCidr}) pointing to VPC peering connection "${route.VpcPeeringConnectionId}". This violates least-privilege network access.`,
              'MEDIUM',
              {
                peeringConnectionId: route.VpcPeeringConnectionId,
                routeTableId,
                destinationCidr
              },
              'Review VPC peering routes and restrict to only the specific CIDR blocks that are required',
              ['vpc', 'peering', 'routing', 'cis-5.4']
            ));
          }
        }
      }
    } catch (error) {
      logger.error('Failed to check VPC peering routes', { error: (error as Error).message });
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
        findings.push(this.createFinding(
          'EBS Default Encryption Not Enabled',
          'EBS default encryption is not enabled. New EBS volumes will not be automatically encrypted at rest.',
          'MEDIUM',
          { ebsEncryptionEnabled: false },
          'Enable EBS default encryption in the EC2 console to automatically encrypt all new EBS volumes',
          ['ec2', 'ebs', 'encryption', 'cis-2.2.1']
        ));
      }
    } catch (error) {
      logger.error('Failed to check EBS default encryption', { error: (error as Error).message });
    }

    return findings;
  }
}

export default VPCScanner;
