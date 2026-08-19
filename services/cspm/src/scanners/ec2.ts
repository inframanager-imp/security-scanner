import {
  DescribeSecurityGroupsCommand,
  DescribeNetworkAclsCommand,
  DescribeInstancesCommand,
  DescribeRouteTablesCommand,
  GetEbsEncryptionByDefaultCommand,
  type Instance,
} from '@aws-sdk/client-ec2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Ports that are always critical to expose to the internet
const ADMIN_PORTS = new Set([22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 5601, 2379, 8500, 6443]);

const PORT_LABELS: Record<number, string> = {
  22: 'SSH',
  3389: 'RDP',
  3306: 'MySQL',
  5432: 'PostgreSQL',
  1433: 'MSSQL',
  27017: 'MongoDB',
  6379: 'Redis',
  9200: 'Elasticsearch',
  5601: 'Kibana',
  2379: 'etcd',
  8500: 'Consul',
  6443: 'Kubernetes API',
};

// Registry checkId for each sensitive admin port (one check per port so the
// per-port titles stay stable).
const PORT_CHECK_IDS: Record<number, string> = {
  22: 'ec2_instance_port_ssh_exposed_to_internet',
  3389: 'ec2_instance_port_rdp_exposed_to_internet',
  3306: 'ec2_instance_port_mysql_exposed_to_internet',
  5432: 'ec2_instance_port_postgresql_exposed_to_internet',
  1433: 'ec2_instance_port_sqlserver_exposed_to_internet',
  27017: 'ec2_instance_port_mongodb_exposed_to_internet',
  6379: 'ec2_instance_port_redis_exposed_to_internet',
  9200: 'ec2_instance_port_elasticsearch_exposed_to_internet',
  5601: 'ec2_instance_port_kibana_exposed_to_internet',
  2379: 'ec2_instance_port_etcd_exposed_to_internet',
  8500: 'ec2_instance_port_consul_exposed_to_internet',
  6443: 'ec2_instance_port_kubernetes_api_exposed_to_internet',
};

export class EC2Scanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'EC2');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting EC2 security scan...');

      const sgFindings = await this.scanSecurityGroups();
      findings.push(...sgFindings);

      const naclFindings = await this.scanNetworkACLs();
      findings.push(...naclFindings);

      const instanceFindings = await this.scanInstances();
      findings.push(...instanceFindings);

      const ebsFindings = await this.checkEBSEncryption();
      findings.push(...ebsFindings);

      const reachabilityFindings = await this.checkNetworkReachability();
      findings.push(...reachabilityFindings);

      logger.info(`EC2 scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('EC2 scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async scanSecurityGroups(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new DescribeSecurityGroupsCommand({ MaxResults: 1000 });
        return await this.client.ec2.send(cmd);
      });

      for (const sg of result.SecurityGroups || []) {
        const sgId = sg.GroupId || 'Unknown';
        const sgName = sg.GroupName || 'Unknown';

        // Collect ALL dangerous open ports for this SG in one pass.
        // Aggregating into a single finding per SG prevents key collisions
        // that would arise from one finding per rule.
        const dangerousOpen: Array<{ port: string; protocol: string }> = [];
        const DANGEROUS_PORTS = new Set(['22', '3389', '3306', '5432', '1433', '27017', '6379', '9200']);

        for (const rule of sg.IpPermissions || []) {
          const openToInternet =
            (rule.IpRanges || []).some((r: any) => r.CidrIp === '0.0.0.0/0') ||
            (rule.Ipv6Ranges || []).some((r: any) => r.CidrIpv6 === '::/0');

          if (!openToInternet) continue;

          const protocol = rule.IpProtocol || 'unknown';

          if (protocol === '-1') {
            dangerousOpen.push({ port: 'all', protocol: 'all' });
          } else {
            const port = String(rule.FromPort ?? 'all');
            if (DANGEROUS_PORTS.has(port) || port === 'all' || port === '-1') {
              dangerousOpen.push({ port, protocol });
            }
          }
        }

        if (dangerousOpen.length > 0) {
          const portSummary = dangerousOpen
            .map((r) => (r.port === 'all' ? 'all traffic' : `port ${r.port}/${r.protocol}`))
            .join(', ');
          findings.push(
            this.emit(
              'ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports',
              { sgId, sgName, openPorts: dangerousOpen },
              {
                message: `Security Group "${sgName}" (${sgId}) allows inbound traffic from 0.0.0.0/0 on: ${portSummary}.`,
                remediation: `Restrict inbound access in "${sgName}" to specific IPs or security groups for: ${portSummary}.`,
              },
            ),
          );
        }
      }
    } catch (error) {
      logger.debug('Failed to scan security groups', { error: (error as Error).message });
    }

    return findings;
  }

  private async scanNetworkACLs(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new DescribeNetworkAclsCommand({ MaxResults: 100 });
        return await this.client.ec2.send(cmd);
      });

      for (const nacl of result.NetworkAcls || []) {
        const naclId = nacl.NetworkAclId || 'Unknown';

        // Aggregate ALL overly permissive entries into one finding per NACL.
        // One finding per entry would create key collisions (all share naclId fingerprint).
        const permissiveEntries = (nacl.Entries || []).filter(
          (e) =>
            e.RuleAction === 'allow' &&
            (e.CidrBlock === '0.0.0.0/0' || e.Ipv6CidrBlock === '::/0'),
        );

        if (permissiveEntries.length > 0) {
          const ruleSummary = permissiveEntries
            .map((e) => `rule ${e.RuleNumber} (${e.Egress ? 'egress' : 'ingress'}, ${e.CidrBlock ?? e.Ipv6CidrBlock})`)
            .join(', ');
          findings.push(
            this.emit(
              'ec2_networkacl_allow_ingress_any_port',
              { naclId, permissiveEntries },
              {
                message: `Network ACL "${naclId}" has ${permissiveEntries.length} rule(s) allowing traffic from 0.0.0.0/0: ${ruleSummary}.`,
                remediation: `Review and restrict Network ACL rules in "${naclId}" to specific CIDR blocks.`,
              },
            ),
          );
        }
      }
    } catch (error) {
      logger.debug('Failed to scan network ACLs', { error: (error as Error).message });
    }

    return findings;
  }

  private async scanInstances(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const result = await retry(async () => {
        const cmd = new DescribeInstancesCommand({ MaxResults: 100 });
        return await this.client.ec2.send(cmd);
      });

      for (const reservation of result.Reservations || []) {
        for (const instance of reservation.Instances || []) {
          const instanceId = instance.InstanceId || 'Unknown';

          // Check for public IP
          if (instance.PublicIpAddress && instance.SecurityGroups?.length === 0) {
            findings.push(this.emit(
              'ec2_instance_public_ip_without_security_group',
              { instanceId, publicIp: instance.PublicIpAddress },
              {
                message: `Instance "${instanceId}" has a public IP but no security group is attached`,
                remediation: `Review and attach appropriate security group to instance "${instanceId}"`,
              }
            ));
          }

          // Check for IMDSv2
          if (instance.MetadataOptions?.HttpTokens !== 'required') {
            findings.push(this.emit(
              'ec2_instance_imdsv2_enabled',
              { instanceId, httpTokens: instance.MetadataOptions?.HttpTokens },
              {
                message: `Instance "${instanceId}" does not enforce IMDSv2 for metadata access`,
                remediation: `Enable IMDSv2 for instance "${instanceId}" to protect against SSRF attacks`,
              }
            ));
          }

          // Check for monitoring
          if (!instance.Monitoring?.State || instance.Monitoring.State === 'disabled') {
            findings.push(this.emit(
              'ec2_instance_detailed_monitoring_enabled',
              { instanceId },
              {
                message: `Instance "${instanceId}" does not have detailed CloudWatch monitoring enabled`,
                remediation: `Enable detailed monitoring for instance "${instanceId}"`,
              }
            ));
          }
        }
      }
    } catch (error) {
      logger.debug('Failed to scan instances', { error: (error as Error).message });
    }

    return findings;
  }

  // ─── Network Reachability Analysis ──────────────────────────────────────────
  // Combines SG inbound rules + route tables + IGW to find instances truly
  // reachable from the internet (not just ones with a public IP).

  private async checkNetworkReachability(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      logger.info('Running network reachability analysis...');

      // Step 1: Find which subnets (and VPCs via main route table) route to an IGW
      const { subnetToIgw, vpcToIgw } = await this.getInternetRoutedSubnets();

      // Step 2: Build SG → open internet rules map
      const sgInternetRules = await this.getSecurityGroupInternetRules();

      // Step 3: Get all running instances
      const instances = await this.getAllRunningInstances();

      for (const instance of instances) {
        const instanceId = instance.InstanceId ?? 'Unknown';
        const publicIp = instance.PublicIpAddress;
        const subnetId = instance.SubnetId ?? '';
        const vpcId = instance.VpcId ?? '';

        if (!publicIp) continue;

        // Determine IGW via explicit subnet association or VPC main route table
        const igwId = subnetToIgw.get(subnetId) ?? vpcToIgw.get(vpcId);
        if (!igwId) continue; // No path to internet gateway

        // Collect all ports open to internet across attached SGs
        const openPorts: Array<{ port: string; protocol: string; sgId: string; sgName: string }> = [];
        for (const sg of instance.SecurityGroups ?? []) {
          const rules = sgInternetRules.get(sg.GroupId ?? '') ?? [];
          for (const rule of rules) {
            openPorts.push({ ...rule, sgId: sg.GroupId ?? '', sgName: sg.GroupName ?? sg.GroupId ?? '' });
          }
        }

        if (openPorts.length === 0) continue; // Public IP + IGW but no open SG rules

        const instanceName = instance.Tags?.find((t) => t.Key === 'Name')?.Value ?? instanceId;
        const hasAllTraffic = openPorts.some((p) => p.port === 'all');
        const adminPorts = openPorts.filter((p) => ADMIN_PORTS.has(parseInt(p.port)));
        const severity = hasAllTraffic || adminPorts.length > 0 ? 'CRITICAL' : 'HIGH';

        const portSummary = openPorts
          .map((p) => (p.port === 'all' ? `all/${p.protocol}` : `${p.port}/${p.protocol}`))
          .join(', ');

        findings.push(
          this.emit(
            'ec2_instance_internet_reachable',
            { instanceId, instanceName, publicIp, vpcId, subnetId, internetGatewayId: igwId, openPorts },
            {
              message: `Instance "${instanceName}" (${instanceId}) is internet-reachable. ` +
                `Public IP: ${publicIp}. Open ports: ${portSummary}. ` +
                `Subnet ${subnetId} routes to internet gateway ${igwId}.`,
              remediation: `Verify "${instanceName}" needs to be publicly accessible. If not, remove the public IP ` +
                `or place it behind a load balancer. Restrict security group rules to specific CIDR ranges.`,
              severity,
            },
          ),
        );

        // One finding per sensitive port for high-signal alerting
        for (const p of adminPorts) {
          const portNum = parseInt(p.port);
          const checkId = PORT_CHECK_IDS[portNum];
          if (!checkId) continue;
          const label = PORT_LABELS[portNum] ?? `port ${portNum}`;
          findings.push(
            this.emit(
              checkId,
              { instanceId, instanceName, publicIp, vpcId, subnetId, port: p.port, protocol: p.protocol, sgId: p.sgId, sgName: p.sgName },
              {
                message: `Instance "${instanceName}" (${instanceId}) has ${label} port ${p.port} open to ` +
                  `0.0.0.0/0 via security group "${p.sgName}" (${p.sgId}).`,
                remediation: `Restrict port ${p.port} in security group "${p.sgName}" immediately. ` +
                  `Use a bastion host, VPN, or AWS Systems Manager Session Manager instead of direct ${label} access.`,
              },
            ),
          );
        }
      }

      logger.info(`Network reachability analysis complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.debug('Network reachability analysis failed', { error: (error as Error).message });
    }
    return findings;
  }

  private async getInternetRoutedSubnets(): Promise<{
    subnetToIgw: Map<string, string>;
    vpcToIgw: Map<string, string>;
  }> {
    const subnetToIgw = new Map<string, string>(); // explicit subnet association → igwId
    const vpcToIgw = new Map<string, string>();    // main route table (VPC-level) → igwId

    let nextToken: string | undefined;
    do {
      const result = await retry(async () =>
        this.client.ec2.send(new DescribeRouteTablesCommand({ NextToken: nextToken })),
      );

      for (const rt of result.RouteTables ?? []) {
        // Check if any route in this table goes to an IGW as the default route
        const igwRoute = (rt.Routes ?? []).find(
          (r) =>
            (r.DestinationCidrBlock === '0.0.0.0/0' || r.DestinationIpv6CidrBlock === '::/0') &&
            r.GatewayId?.startsWith('igw-') &&
            r.State === 'active',
        );
        if (!igwRoute) continue;

        const igwId = igwRoute.GatewayId!;
        const vpcId = rt.VpcId ?? '';

        for (const assoc of rt.Associations ?? []) {
          if (assoc.SubnetId) {
            // Explicit subnet association
            subnetToIgw.set(assoc.SubnetId, igwId);
          } else if (assoc.Main) {
            // Main route table — applies to subnets with no explicit association
            vpcToIgw.set(vpcId, igwId);
          }
        }
      }

      nextToken = result.NextToken;
    } while (nextToken);

    return { subnetToIgw, vpcToIgw };
  }

  private async getSecurityGroupInternetRules(): Promise<
    Map<string, Array<{ port: string; protocol: string }>>
  > {
    const sgRules = new Map<string, Array<{ port: string; protocol: string }>>();

    let nextToken: string | undefined;
    do {
      const result = await retry(async () =>
        this.client.ec2.send(
          new DescribeSecurityGroupsCommand({ MaxResults: 1000, NextToken: nextToken }),
        ),
      );

      for (const sg of result.SecurityGroups ?? []) {
        const sgId = sg.GroupId ?? '';
        const openRules: Array<{ port: string; protocol: string }> = [];

        for (const rule of sg.IpPermissions ?? []) {
          const openToInternet =
            (rule.IpRanges ?? []).some((r) => r.CidrIp === '0.0.0.0/0') ||
            (rule.Ipv6Ranges ?? []).some((r) => r.CidrIpv6 === '::/0');

          if (!openToInternet) continue;

          if (rule.IpProtocol === '-1') {
            openRules.push({ port: 'all', protocol: 'all' });
          } else if (rule.FromPort !== undefined && rule.ToPort !== undefined) {
            const protocol = rule.IpProtocol ?? 'tcp';
            if (rule.FromPort === rule.ToPort) {
              openRules.push({ port: String(rule.FromPort), protocol });
            } else {
              // Port range — flag if it includes any admin port
              for (const adminPort of ADMIN_PORTS) {
                if (adminPort >= rule.FromPort && adminPort <= rule.ToPort) {
                  openRules.push({ port: String(adminPort), protocol });
                }
              }
              // Also record the range itself
              openRules.push({ port: `${rule.FromPort}-${rule.ToPort}`, protocol });
            }
          }
        }

        if (openRules.length > 0) sgRules.set(sgId, openRules);
      }

      nextToken = result.NextToken;
    } while (nextToken);

    return sgRules;
  }

  private async getAllRunningInstances(): Promise<Instance[]> {
    const instances: Instance[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () =>
        this.client.ec2.send(
          new DescribeInstancesCommand({
            Filters: [{ Name: 'instance-state-name', Values: ['running'] }],
            NextToken: nextToken,
          }),
        ),
      );
      for (const reservation of result.Reservations ?? []) {
        instances.push(...(reservation.Instances ?? []));
      }
      nextToken = result.NextToken;
    } while (nextToken);
    return instances;
  }

  // ─── EBS Encryption ──────────────────────────────────────────────────────────

  private async checkEBSEncryption(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const result = await retry(async () => {
        return await this.client.ec2.send(new GetEbsEncryptionByDefaultCommand({}));
      });
      if (!result.EbsEncryptionByDefault) {
        findings.push(this.emit(
          'ec2_ebs_default_encryption',
          { ebsEncryptionByDefault: false, region: this.client.getRegion() },
          {
            message: 'EBS default encryption is not enabled for this region. New EBS volumes will not be automatically encrypted.',
          }
        ));
      }
    } catch (error) {
      logger.debug('Failed to check EBS default encryption', { error: (error as Error).message });
    }
    return findings;
  }
}

export default EC2Scanner;
