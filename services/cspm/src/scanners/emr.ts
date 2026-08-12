// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  EMRClient,
  ListClustersCommand,
  DescribeClusterCommand,
  GetBlockPublicAccessConfigurationCommand,
} from '@aws-sdk/client-emr';
import { EC2Client, DescribeSecurityGroupsCommand } from '@aws-sdk/client-ec2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const TERMINATED_STATES = ['TERMINATED', 'TERMINATED_WITH_ERRORS'];

/**
 * Port of Prowler's _is_cidr_public with any_address=False: 0.0.0.0/0 and ::/0
 * are public, as is any globally routable CIDR (approximated by excluding
 * well-known private/reserved ranges).
 */
function isPublicCidr(cidr: string | undefined): boolean {
  if (!cidr) return false;
  if (cidr === '0.0.0.0/0' || cidr === '::/0') return true;
  const ip = cidr.split('/')[0];
  if (ip.includes(':')) {
    // IPv6: unique-local (fc00::/7) and link-local (fe80::/10) are not global
    const lower = ip.toLowerCase();
    if (lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe8') ||
        lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb') ||
        lower === '::1' || lower === '::') {
      return false;
    }
    return true;
  }
  const octets = ip.split('.').map((o) => parseInt(o, 10));
  if (octets.length !== 4 || octets.some((o) => isNaN(o))) return false;
  const [a, b] = octets;
  if (a === 10 || a === 127 || a === 0) return false;               // 10/8, loopback, "this network"
  if (a === 172 && b >= 16 && b <= 31) return false;                 // 172.16/12
  if (a === 192 && b === 168) return false;                          // 192.168/16
  if (a === 169 && b === 254) return false;                          // link-local
  if (a === 100 && b >= 64 && b <= 127) return false;                // CGNAT 100.64/10
  return true;
}

/**
 * Port of Prowler's check_security_group(ingress_rule, "-1"): a rule is public
 * when it is an all-traffic rule (IpProtocol -1) with a public CIDR, or when it
 * opens the full port range (0-65535) to a public CIDR.
 */
function isIngressRulePublic(rule: any): boolean {
  const ipRanges: any[] = rule.IpRanges ?? [];
  const ipv6Ranges: any[] = rule.Ipv6Ranges ?? [];
  const cidrs: string[] = [
    ...ipRanges.map((r) => r.CidrIp),
    ...ipv6Ranges.map((r) => r.CidrIpv6),
  ];
  const hasPublicCidr = cidrs.some((c) => isPublicCidr(c));
  if (!hasPublicCidr) return false;

  if (rule.IpProtocol === '-1') return true;

  if (rule.FromPort !== undefined && rule.ToPort !== undefined) {
    // Public only when the rule spans the entire port range
    return rule.ToPort - rule.FromPort + 1 === 65536;
  }
  return false;
}

export class EMRScanner extends BaseScanner {
  private emr: EMRClient;
  private ec2: EC2Client;

  constructor(client: AWSClient) {
    super(client, 'EMR');
    this.emr = new EMRClient(client.getClientConfig());
    this.ec2 = new EC2Client(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting EMR security scan...');

      // Account/region-level Block Public Access configuration
      try {
        findings.push(...(await this.checkBlockPublicAccess()));
      } catch (error) {
        logger.debug('Failed to get EMR block public access configuration', { error: (error as Error).message });
      }

      const clusters = await this.listClusters();
      const activeClusters = clusters.filter(
        (c: any) => !TERMINATED_STATES.includes(c.Status?.State ?? '')
      );
      logger.info(`EMR: scanning ${activeClusters.length} active cluster(s)`);

      for (const cluster of activeClusters) {
        try {
          findings.push(...(await this.validateCluster(cluster)));
        } catch (error) {
          logger.debug(`Failed to scan EMR cluster ${cluster.Id}`, { error: (error as Error).message });
        }
      }

      logger.info(`EMR scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('EMR scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listClusters(): Promise<any[]> {
    const clusters: any[] = [];
    let marker: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.emr.send(new ListClustersCommand({ Marker: marker }));
      });
      clusters.push(...(result.Clusters ?? []));
      marker = result.Marker;
    } while (marker);
    return clusters;
  }

  private async checkBlockPublicAccess(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const region = this.client.getRegion();

    const result = await retry(async () => {
      return await this.emr.send(new GetBlockPublicAccessConfigurationCommand({}));
    });
    const blockPublicSecurityGroupRules =
      result.BlockPublicAccessConfiguration?.BlockPublicSecurityGroupRules ?? false;

    // emr_cluster_account_public_block_enabled: account must block public SG rules
    if (!blockPublicSecurityGroupRules) {
      findings.push(this.emit(
        'emr_cluster_account_public_block_enabled',
        { region, blockPublicSecurityGroupRules: false },
        {
          message: `EMR account has Block Public Access disabled in region ${region}`,
          remediation: `Enable EMR Block Public Access in region ${region}: aws emr put-block-public-access-configuration --block-public-access-configuration BlockPublicSecurityGroupRules=true`,
        }
      ));
    }

    return findings;
  }

  private async validateCluster(clusterSummary: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const clusterId: string = clusterSummary.Id ?? '';
    const clusterArn: string = clusterSummary.ClusterArn ?? clusterId;

    const result = await retry(async () => {
      return await this.emr.send(new DescribeClusterCommand({ ClusterId: clusterId }));
    });
    const cluster: any = result.Cluster;
    if (!cluster) return findings;

    const ec2Attributes: any = cluster.Ec2InstanceAttributes ?? {};
    const masterPublicDnsName: string = cluster.MasterPublicDnsName ?? '';
    // Public EMR clusters have their master DNS ending with .amazonaws.com,
    // private ones look like ip-x-x-x-x.<region>.compute.internal
    const isPublic = masterPublicDnsName.includes('.amazonaws.com');

    // emr_cluster_master_nodes_no_public_ip
    if (isPublic) {
      findings.push(this.emit(
        'emr_cluster_master_nodes_no_public_ip',
        { resourceId: clusterArn, clusterId, clusterName: cluster.Name, masterPublicDnsName },
        {
          message: `EMR cluster "${clusterId}" has a public IP (master public DNS: ${masterPublicDnsName})`,
          remediation: `Relaunch cluster "${clusterId}" into a private subnet so its nodes only receive private addresses`,
        }
      ));
    }

    // emr_cluster_publicly_accesible: only public clusters need SG evaluation
    if (isPublic) {
      const masterSecurityGroups: string[] = [
        ...(ec2Attributes.AdditionalMasterSecurityGroups ?? []),
        ...(ec2Attributes.EmrManagedMasterSecurityGroup ? [ec2Attributes.EmrManagedMasterSecurityGroup] : []),
      ];
      const slaveSecurityGroups: string[] = [
        ...(ec2Attributes.AdditionalSlaveSecurityGroups ?? []),
        ...(ec2Attributes.EmrManagedSlaveSecurityGroup ? [ec2Attributes.EmrManagedSlaveSecurityGroup] : []),
      ];

      const masterPublicSgs = await this.findPublicSecurityGroups(masterSecurityGroups);
      const slavePublicSgs = await this.findPublicSecurityGroups(slaveSecurityGroups);

      if (masterPublicSgs.length > 0 || slavePublicSgs.length > 0) {
        const parts: string[] = [];
        if (masterPublicSgs.length > 0) parts.push(`master node [${masterPublicSgs.join(', ')}]`);
        if (slavePublicSgs.length > 0) parts.push(`worker nodes [${slavePublicSgs.join(', ')}]`);
        findings.push(this.emit(
          'emr_cluster_publicly_accesible',
          {
            resourceId: clusterArn,
            clusterId,
            clusterName: cluster.Name,
            masterPublicSecurityGroups: masterPublicSgs,
            slavePublicSecurityGroups: slavePublicSgs,
          },
          {
            message: `EMR cluster "${clusterId}" is publicly accessible through the following security groups: ${parts.join(', ')}`,
            remediation: `Remove unrestricted public ingress rules from the security groups attached to cluster "${clusterId}" (${[...masterPublicSgs, ...slavePublicSgs].join(', ')})`,
          }
        ));
      }
    }

    return findings;
  }

  private async findPublicSecurityGroups(securityGroupIds: string[]): Promise<string[]> {
    const uniqueIds = [...new Set(securityGroupIds.filter((id) => !!id))];
    if (uniqueIds.length === 0) return [];

    const publicSgs: string[] = [];
    try {
      const result = await retry(async () => {
        return await this.ec2.send(new DescribeSecurityGroupsCommand({ GroupIds: uniqueIds }));
      });
      for (const sg of result.SecurityGroups ?? []) {
        const rules: any[] = sg.IpPermissions ?? [];
        if (rules.some((rule) => isIngressRulePublic(rule)) && sg.GroupId) {
          publicSgs.push(sg.GroupId);
        }
      }
    } catch (error) {
      logger.debug(`Failed to describe EMR security groups ${uniqueIds.join(', ')}`, { error: (error as Error).message });
    }
    return publicSgs;
  }
}

export default EMRScanner;
