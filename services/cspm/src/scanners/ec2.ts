// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  DescribeSecurityGroupsCommand,
  DescribeNetworkAclsCommand,
  DescribeInstancesCommand,
  DescribeRouteTablesCommand,
  DescribeAddressesCommand,
  DescribeImagesCommand,
  DescribeVolumesCommand,
  DescribeSnapshotsCommand,
  DescribeNetworkInterfacesCommand,
  DescribeLaunchTemplatesCommand,
  DescribeLaunchTemplateVersionsCommand,
  DescribeClientVpnEndpointsCommand,
  DescribeTransitGatewaysCommand,
  DescribeInstanceAttributeCommand,
  GetEbsEncryptionByDefaultCommand,
  GetImageBlockPublicAccessStateCommand,
  GetSnapshotBlockPublicAccessStateCommand,
  GetInstanceMetadataDefaultsCommand,
  type Instance,
} from '@aws-sdk/client-ec2';
import { BackupClient, ListProtectedResourcesCommand } from '@aws-sdk/client-backup';
import { gunzipSync } from 'zlib';
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

// ─── Prowler-ported check tables and helpers ────────────────────────────────

// Prowler audit-config defaults
const MAX_INSTANCE_AGE_DAYS = 180;      // max_ec2_instance_age_in_days
const MAX_INSTANCE_STOPPED_DAYS = 30;   // max_ec2_instance_stopped_days
const MAX_SG_RULES = 50;                // max_security_group_rules
const ENCLAVE_ALLOWED_PORTS = new Set([22, 80, 443]);   // enclave_sg_allow_ports
const ENCLAVE_INGRESS_SUMMARY_THRESHOLD = 10;
const VSOCK_PORTS: number[] = [5000, ...Array.from({ length: 91 }, (_, i) => 8000 + i), 9000]; // enclave_vsock_ports
const SG_ALLOWED_ENI_TYPES = new Set(['api_gateway_managed', 'vpc_endpoint']); // ec2_allowed_interface_types
const SG_ALLOWED_INSTANCE_OWNERS = new Set(['amazon-elb']);                    // ec2_allowed_instance_owners

const ENCLAVE_TERMINAL_STATES = new Set(['stopped', 'shutting-down', 'terminated']);

// ec2_instance_port_*_exposed_to_internet family (Prowler check_ports tables)
const INSTANCE_PORT_CHECKS: Array<{ checkId: string; label: string; ports: number[] }> = [
  { checkId: 'ec2_instance_port_cassandra_exposed_to_internet', label: 'Cassandra', ports: [7000, 7001, 7199, 9042, 9160] },
  { checkId: 'ec2_instance_port_cifs_exposed_to_internet', label: 'CIFS', ports: [139, 445] },
  { checkId: 'ec2_instance_port_elasticsearch_kibana_exposed_to_internet', label: 'Elasticsearch/Kibana', ports: [9200, 9300, 5601] },
  { checkId: 'ec2_instance_port_ftp_exposed_to_internet', label: 'FTP', ports: [20, 21] },
  { checkId: 'ec2_instance_port_kafka_exposed_to_internet', label: 'Kafka', ports: [9092] },
  { checkId: 'ec2_instance_port_kerberos_exposed_to_internet', label: 'Kerberos', ports: [88, 464, 749, 750] },
  { checkId: 'ec2_instance_port_ldap_exposed_to_internet', label: 'LDAP', ports: [389, 636] },
  { checkId: 'ec2_instance_port_memcached_exposed_to_internet', label: 'Memcached', ports: [11211] },
  { checkId: 'ec2_instance_port_oracle_exposed_to_internet', label: 'Oracle', ports: [1521, 2483, 2484] },
  { checkId: 'ec2_instance_port_telnet_exposed_to_internet', label: 'Telnet', ports: [23] },
];

// ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_* family
const SG_PORT_CHECKS: Array<{ checkId: string; label: string; ports: number[] }> = [
  { checkId: 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22', label: 'SSH port 22', ports: [22] },
  { checkId: 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389', label: 'Microsoft RDP port 3389', ports: [3389] },
  { checkId: 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888', label: 'Cassandra ports 7199, 9160, 8888', ports: [7199, 9160, 8888] },
  { checkId: 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601', label: 'Elasticsearch/Kibana ports 9200, 9300, 5601', ports: [9200, 9300, 5601] },
  { checkId: 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_ftp_20_21', label: 'FTP ports 20, 21', ports: [20, 21] },
  { checkId: 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092', label: 'Kafka port 9092', ports: [9092] },
  { checkId: 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211', label: 'Memcached port 11211', ports: [11211] },
  { checkId: 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mongodb_27017_27018', label: 'MongoDB ports 27017, 27018', ports: [27017, 27018] },
  { checkId: 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306', label: 'MySQL port 3306', ports: [3306] },
  { checkId: 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483', label: 'Oracle ports 1521, 2483', ports: [1521, 2483] },
  { checkId: 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432', label: 'PostgreSQL port 5432', ports: [5432] },
  { checkId: 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379', label: 'Redis port 6379', ports: [6379] },
  { checkId: 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434', label: 'SQL Server ports 1433, 1434', ports: [1433, 1434] },
  { checkId: 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23', label: 'Telnet port 23', ports: [23] },
];

const NACL_PORT_CHECKS: Array<{ checkId: string; label: string; port: number }> = [
  { checkId: 'ec2_networkacl_allow_ingress_tcp_port_22', label: 'SSH', port: 22 },
  { checkId: 'ec2_networkacl_allow_ingress_tcp_port_3389', label: 'Microsoft RDP', port: 3389 },
];

// Lightweight secret heuristics (Prowler uses a full secret scanner; we match
// well-known credential formats and secret-like assignments in user data).
const SECRET_CONTENT_PATTERNS: { label: string; pattern: RegExp }[] = [
  { label: 'AWS Access Key ID', pattern: /(?:AKIA|ASIA)[0-9A-Z]{16}/ },
  { label: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/ },
  {
    label: 'Secret Assignment',
    pattern: /(?:password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret)\s*[=:]\s*['"]?[^\s'"]{6,}/i,
  },
];

function findSecretsInText(text: string): string[] {
  const matches: string[] = [];
  for (const { label, pattern } of SECRET_CONTENT_PATTERNS) {
    if (pattern.test(text)) matches.push(label);
  }
  return matches;
}

/** Base64 (optionally gzipped, as in Prowler) user data → text, or null when undecodable. */
function decodeUserData(userData: string): string | null {
  try {
    let buffer = Buffer.from(userData, 'base64');
    if (buffer.length > 2 && buffer[0] === 0x1f && buffer[1] === 0x8b) {
      buffer = gunzipSync(buffer);
    }
    return buffer.toString('utf-8');
  } catch {
    return null;
  }
}

function ruleOpenToInternet(rule: any): boolean {
  return (
    (rule.IpRanges ?? []).some((r: any) => r.CidrIp === '0.0.0.0/0') ||
    (rule.Ipv6Ranges ?? []).some((r: any) => r.CidrIpv6 === '::/0')
  );
}

/** True when the ingress rule covers any of the given TCP ports (Prowler check_security_group semantics). */
function ruleMatchesTcpPorts(rule: any, ports: number[]): boolean {
  if (rule.IpProtocol === '-1') return true;
  if (rule.IpProtocol !== 'tcp') return false;
  if (rule.FromPort === undefined || rule.ToPort === undefined) return true;
  return ports.some((port) => port >= rule.FromPort && port <= rule.ToPort);
}

/** Prowler lib.enclave rule_world_facing_port_range equivalent. */
function worldFacingPortRange(rule: any, protocols: string[]): 'all' | [number, number] | null {
  if (!ruleOpenToInternet(rule)) return null;
  if (rule.IpProtocol === '-1') return 'all';
  if (!protocols.includes(rule.IpProtocol)) return null;
  if (rule.FromPort === undefined || rule.ToPort === undefined) return 'all';
  return [rule.FromPort, rule.ToPort];
}

// Non-global IPv4 ranges per python ipaddress is_global (private, reserved, documentation, multicast...)
const NON_GLOBAL_IPV4_RANGES: Array<[string, number]> = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255 || part === '') return null;
    value = value * 256 + n;
  }
  return value;
}

function isPublicIpv4(ip: string): boolean {
  const value = ipv4ToInt(ip);
  if (value === null) return false;
  for (const [base, maskBits] of NON_GLOBAL_IPV4_RANGES) {
    const baseInt = ipv4ToInt(base);
    if (baseInt === null) continue;
    const shift = 32 - maskBits;
    if (value >>> shift === baseInt >>> shift) return false;
  }
  return true;
}

function isGlobalIpv6(address: string): boolean {
  const a = address.toLowerCase();
  return !(a.startsWith('fe80') || a.startsWith('fc') || a.startsWith('fd') || a === '::1' || a === '::');
}

/** Public (non-RFC1918) IPv4 CIDR wider than /24, per ec2_securitygroup_allow_wide_open_public_ipv4. */
function isWideOpenPublicCidr(cidr: string): boolean {
  const [base, prefixStr] = cidr.split('/');
  const prefix = Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix <= 0 || prefix >= 24) return false;
  return isPublicIpv4(base);
}

function findWideOpenPublicCidr(
  rules: any[],
  direction: 'ingress' | 'egress',
): { cidr: string; direction: string } | null {
  for (const rule of rules) {
    for (const range of rule.IpRanges ?? []) {
      const cidr: string = range.CidrIp ?? '';
      if (cidr && isWideOpenPublicCidr(cidr)) return { cidr, direction };
    }
  }
  return null;
}

/** First ingress source that is a specific (non-wildcard) globally routable IP CIDR, or null. */
function findSpecificPublicSource(rules: any[]): string | null {
  for (const rule of rules) {
    for (const range of rule.IpRanges ?? []) {
      const cidr: string = range.CidrIp ?? '';
      if (cidr && cidr !== '0.0.0.0/0' && isPublicIpv4(cidr.split('/')[0])) return cidr;
    }
    for (const range of rule.Ipv6Ranges ?? []) {
      const cidr: string = range.CidrIpv6 ?? '';
      if (cidr && cidr !== '::/0' && isGlobalIpv6(cidr.split('/')[0])) return cidr;
    }
  }
  return null;
}

function eniHasPublicIp(eni: any): boolean {
  if (eni.Association?.PublicIp) return true;
  for (const privateIp of eni.PrivateIpAddresses ?? []) {
    if (privateIp.Association?.PublicIp) return true;
  }
  for (const ipv6 of eni.Ipv6Addresses ?? []) {
    if (ipv6.Ipv6Address && isGlobalIpv6(ipv6.Ipv6Address)) return true;
  }
  return false;
}

// AWS StateTransitionReason for stopped instances, e.g. "User initiated (2016-09-14 15:07:39 GMT)"
const STATE_TRANSITION_TIME_REGEX = /\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)/;

function parseStateTransitionTime(reason: string | undefined): number | null {
  if (!reason) return null;
  const match = STATE_TRANSITION_TIME_REGEX.exec(reason);
  if (!match) return null;
  const timestamp = Date.parse(`${match[1].replace(' ', 'T')}Z`);
  return Number.isNaN(timestamp) ? null : timestamp;
}

/**
 * Prowler get_instance_public_status severity escalation: medium when the
 * instance has no public IP, high with a public IP in a private subnet,
 * critical with a public IP in an internet-routed subnet.
 */
function instanceExposure(
  instance: any,
  publicSubnet: boolean,
): { severity: 'MEDIUM' | 'HIGH' | 'CRITICAL'; detail: string } {
  if (!instance.PublicIpAddress) {
    return { severity: 'MEDIUM', detail: ', but the instance has no public IP address' };
  }
  if (publicSubnet) {
    return { severity: 'CRITICAL', detail: ` on public IP ${instance.PublicIpAddress} in an internet-routed subnet` };
  }
  return { severity: 'HIGH', detail: ` on public IP ${instance.PublicIpAddress}, though its subnet has no internet gateway route` };
}

/**
 * NACL evaluation: first matching rule (by rule number) wins; IPv4 and IPv6
 * wildcard sources are evaluated independently. Returns true when the ACL
 * ends up allowing internet ingress to the given TCP port.
 */
function naclAllowsIngressTcpPort(entries: any[], port: number): boolean {
  for (const family of ['v4', 'v6'] as const) {
    const candidates = entries
      .filter((entry: any) =>
        !entry.Egress &&
        (family === 'v4' ? entry.CidrBlock === '0.0.0.0/0' : entry.Ipv6CidrBlock === '::/0'))
      .sort((a: any, b: any) => (a.RuleNumber ?? 0) - (b.RuleNumber ?? 0));
    for (const entry of candidates) {
      const protocolMatches =
        entry.Protocol === '-1' ||
        (entry.Protocol === '6' &&
          (!entry.PortRange || ((entry.PortRange.From ?? 0) <= port && port <= (entry.PortRange.To ?? 65535))));
      if (!protocolMatches) continue;
      if (entry.RuleAction === 'allow') return true;
      break; // an earlier deny shadows later allows for this source
    }
  }
  return false;
}

export class EC2Scanner extends BaseScanner {
  private backup: BackupClient;

  constructor(client: AWSClient) {
    super(client, 'EC2');
    this.backup = new BackupClient(client.getClientConfig());
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

      const portedFindings = await this.runPortedChecks();
      findings.push(...portedFindings);

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

  // ─── Prowler-ported checks ──────────────────────────────────────────────────
  // Shared state (instances, security groups, ENIs, route tables, volumes,
  // snapshots) is collected once; each check group then runs off it.

  private async runPortedChecks(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    let instances: any[] = [];
    let securityGroups: any[] = [];
    let networkInterfaces: any[] = [];
    let volumes: any[] = [];
    let snapshots: any[] = [];
    let subnetToIgw = new Map<string, string>();
    let vpcToIgw = new Map<string, string>();

    try { instances = await this.getAllInstancesAnyState(); } catch (error) {
      logger.debug('Failed to describe EC2 instances', { error: (error as Error).message });
    }
    try { securityGroups = await this.getAllSecurityGroups(); } catch (error) {
      logger.debug('Failed to describe security groups', { error: (error as Error).message });
    }
    try { networkInterfaces = await this.getAllNetworkInterfaces(); } catch (error) {
      logger.debug('Failed to describe network interfaces', { error: (error as Error).message });
    }
    try { volumes = await this.getAllVolumes(); } catch (error) {
      logger.debug('Failed to describe EBS volumes', { error: (error as Error).message });
    }
    try { snapshots = await this.getSelfSnapshots(); } catch (error) {
      logger.debug('Failed to describe EBS snapshots', { error: (error as Error).message });
    }
    try {
      const routed = await this.getInternetRoutedSubnets();
      subnetToIgw = routed.subnetToIgw;
      vpcToIgw = routed.vpcToIgw;
    } catch (error) {
      logger.debug('Failed to describe route tables', { error: (error as Error).message });
    }

    const sgById = new Map<string, any>();
    for (const sg of securityGroups) {
      if (sg.GroupId) sgById.set(sg.GroupId, sg);
    }

    const enisBySg = new Map<string, any[]>();
    const eniById = new Map<string, any>();
    for (const eni of networkInterfaces) {
      if (eni.NetworkInterfaceId) eniById.set(eni.NetworkInterfaceId, eni);
      for (const group of eni.Groups ?? []) {
        if (!group.GroupId) continue;
        const list = enisBySg.get(group.GroupId) ?? [];
        list.push(eni);
        enisBySg.set(group.GroupId, list);
      }
    }

    const isPublicSubnet = (subnetId: string, vpcId: string): boolean =>
      subnetToIgw.has(subnetId) || vpcToIgw.has(vpcId);

    const groups: Array<{ label: string; run: () => Promise<ScanningResult[]> }> = [
      { label: 'account settings', run: () => this.checkAccountLevelSettings(instances, snapshots) },
      { label: 'AMIs', run: () => this.checkAmis(instances) },
      { label: 'EBS volumes', run: () => this.checkVolumes(volumes, snapshots) },
      { label: 'Elastic IPs', run: () => this.checkElasticIps() },
      { label: 'Client VPN endpoints', run: () => this.checkClientVpnEndpoints() },
      { label: 'Transit Gateways', run: () => this.checkTransitGateways() },
      { label: 'instance hygiene', run: async () => this.checkInstanceHygiene(instances) },
      { label: 'instance port exposure', run: async () => this.checkInstancePortExposure(instances, sgById, isPublicSubnet) },
      { label: 'confidential workload hosts', run: async () => this.checkConfidentialWorkloadHosts(instances, sgById, isPublicSubnet) },
      { label: 'security group rules', run: async () => this.checkSecurityGroupRules(securityGroups, enisBySg) },
      { label: 'network ACLs', run: () => this.checkNetworkAclRules() },
      { label: 'launch templates', run: () => this.checkLaunchTemplates(eniById) },
      { label: 'instance user data secrets', run: () => this.checkInstanceUserDataSecrets(instances) },
    ];

    for (const group of groups) {
      try {
        findings.push(...(await group.run()));
      } catch (error) {
        logger.debug(`EC2 ported check group failed: ${group.label}`, { error: (error as Error).message });
      }
    }

    return findings;
  }

  // ── State fetchers ──

  private async getAllInstancesAnyState(): Promise<any[]> {
    const instances: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () =>
        this.client.ec2.send(new DescribeInstancesCommand({ NextToken: nextToken })),
      );
      for (const reservation of result.Reservations ?? []) {
        instances.push(...(reservation.Instances ?? []));
      }
      nextToken = result.NextToken;
    } while (nextToken);
    return instances;
  }

  private async getAllSecurityGroups(): Promise<any[]> {
    const securityGroups: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () =>
        this.client.ec2.send(new DescribeSecurityGroupsCommand({ MaxResults: 1000, NextToken: nextToken })),
      );
      securityGroups.push(...(result.SecurityGroups ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return securityGroups;
  }

  private async getAllNetworkInterfaces(): Promise<any[]> {
    const interfaces: any[] = [];
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () =>
        this.client.ec2.send(new DescribeNetworkInterfacesCommand({ NextToken: nextToken })),
      );
      interfaces.push(...(result.NetworkInterfaces ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return interfaces;
  }

  private async getAllNetworkAcls(): Promise<any[]> {
    const nacls: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () =>
        this.client.ec2.send(new DescribeNetworkAclsCommand({ NextToken: nextToken })),
      );
      nacls.push(...(result.NetworkAcls ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return nacls;
  }

  private async getAllVolumes(): Promise<any[]> {
    const volumes: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () =>
        this.client.ec2.send(new DescribeVolumesCommand({ NextToken: nextToken })),
      );
      volumes.push(...(result.Volumes ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return volumes;
  }

  private async getSelfSnapshots(): Promise<any[]> {
    const snapshots: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () =>
        this.client.ec2.send(new DescribeSnapshotsCommand({ OwnerIds: ['self'], NextToken: nextToken })),
      );
      snapshots.push(...(result.Snapshots ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return snapshots;
  }

  private async getAllLaunchTemplates(): Promise<any[]> {
    const templates: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () =>
        this.client.ec2.send(new DescribeLaunchTemplatesCommand({ NextToken: nextToken })),
      );
      templates.push(...(result.LaunchTemplates ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return templates;
  }

  private async getLaunchTemplateVersions(templateId: string): Promise<any[]> {
    const versions: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () =>
        this.client.ec2.send(
          new DescribeLaunchTemplateVersionsCommand({ LaunchTemplateId: templateId, NextToken: nextToken }),
        ),
      );
      versions.push(...(result.LaunchTemplateVersions ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return versions;
  }

  private async getBackupProtectedResourceArns(): Promise<Set<string>> {
    const arns = new Set<string>();
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () =>
        this.backup.send(new ListProtectedResourcesCommand({ NextToken: nextToken })),
      );
      for (const resource of result.Results ?? []) {
        if (resource.ResourceArn) arns.add(resource.ResourceArn);
      }
      nextToken = result.NextToken;
    } while (nextToken);
    return arns;
  }

  // ── Account-level settings ──

  private async checkAccountLevelSettings(instances: any[], snapshots: any[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const region = this.client.getRegion();

    // ec2_ami_account_block_public_access
    try {
      const result = await retry(async () =>
        this.client.ec2.send(new GetImageBlockPublicAccessStateCommand({})),
      );
      const state: string = result.ImageBlockPublicAccessState ?? 'unblocked';
      if (state !== 'block-new-sharing') {
        findings.push(this.emit(
          'ec2_ami_account_block_public_access',
          { region, imageBlockPublicAccessState: state },
          {
            message: `AMI Block Public Access is disabled in region ${region}, so AMIs can be shared publicly`,
            remediation: `Run "aws ec2 enable-image-block-public-access --image-block-public-access-state block-new-sharing" in region ${region} and add SCP guardrails so it cannot be disabled`,
          },
        ));
      }
    } catch (error) {
      logger.debug('Failed to check AMI block public access state', { error: (error as Error).message });
    }

    // ec2_ebs_snapshot_account_block_public_access (only when the region has snapshots, as in Prowler)
    if (snapshots.length > 0) {
      try {
        const result = await retry(async () =>
          this.client.ec2.send(new GetSnapshotBlockPublicAccessStateCommand({})),
        );
        const state: string = result.State ?? 'unblocked';
        if (state !== 'block-all-sharing') {
          const detail = state === 'block-new-sharing'
            ? 'public access is blocked only for newly shared EBS snapshots'
            : 'public access is not blocked for EBS snapshots';
          findings.push(this.emit(
            'ec2_ebs_snapshot_account_block_public_access',
            { region, snapshotBlockPublicAccessState: state },
            {
              message: `In region ${region}, ${detail}`,
              remediation: `Run "aws ec2 enable-snapshot-block-public-access --state block-all-sharing" in region ${region} and review snapshots that are already shared publicly`,
            },
          ));
        }
      } catch (error) {
        logger.debug('Failed to check EBS snapshot block public access state', { error: (error as Error).message });
      }
    }

    // ec2_instance_account_imdsv2_enabled (only when the region has instances, as in Prowler)
    if (instances.length > 0) {
      try {
        const result: any = await retry(async () =>
          this.client.ec2.send(new GetInstanceMetadataDefaultsCommand({})),
        );
        const httpTokens: string | undefined = result.AccountLevel?.HttpTokens;
        if (httpTokens !== 'required') {
          findings.push(this.emit(
            'ec2_instance_account_imdsv2_enabled',
            { region, accountLevelHttpTokens: httpTokens ?? null },
            {
              message: `IMDSv2 is not enabled by default for new EC2 instances in region ${region}`,
              remediation: `Run "aws ec2 modify-instance-metadata-defaults --region ${region} --http-tokens required" so new instances enforce IMDSv2 by default`,
            },
          ));
        }
      } catch (error) {
        logger.debug('Failed to check account instance metadata defaults', { error: (error as Error).message });
      }
    }

    return findings;
  }

  // ── AMIs ──

  private async checkAmis(instances: any[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    // ec2_ami_public: self-owned AMIs must not be publicly shared
    try {
      const result = await retry(async () =>
        this.client.ec2.send(new DescribeImagesCommand({ Owners: ['self'], IncludeDeprecated: true })),
      );
      for (const image of result.Images ?? []) {
        if (!image.Public) continue;
        const imageId = image.ImageId ?? 'Unknown';
        const name = image.Name || imageId;
        findings.push(this.emit(
          'ec2_ami_public',
          { imageId, name: image.Name ?? null },
          {
            message: `EC2 AMI "${name}" (${imageId}) is publicly shared`,
            remediation: `Make AMI ${imageId} private: aws ec2 modify-image-attribute --image-id ${imageId} --launch-permission "Remove=[{Group=all}]"`,
          },
        ));
      }
    } catch (error) {
      logger.debug('Failed to check public AMIs', { error: (error as Error).message });
    }

    // ec2_instance_with_outdated_ami: instances on Amazon-owned AMIs past their deprecation time
    try {
      const imageIds = [...new Set(instances.map((i) => i.ImageId).filter(Boolean))] as string[];
      if (imageIds.length > 0) {
        const images = await this.describeImagesByIds(imageIds);
        const now = Date.now();
        const deprecatedAmis = new Map<string, any>();
        for (const image of images) {
          if (image.ImageOwnerAlias !== 'amazon' || !image.DeprecationTime || !image.ImageId) continue;
          const deprecation = Date.parse(image.DeprecationTime);
          if (!Number.isNaN(deprecation) && deprecation < now) deprecatedAmis.set(image.ImageId, image);
        }
        for (const instance of instances) {
          const ami = deprecatedAmis.get(instance.ImageId ?? '');
          if (!ami) continue;
          const instanceId = instance.InstanceId ?? 'Unknown';
          findings.push(this.emit(
            'ec2_instance_with_outdated_ami',
            { instanceId, imageId: ami.ImageId, deprecationTime: ami.DeprecationTime },
            {
              message: `EC2 Instance "${instanceId}" is using deprecated Amazon AMI ${ami.ImageId} (deprecated since ${ami.DeprecationTime})`,
              remediation: `Rebuild instance "${instanceId}" from a current, non-deprecated AMI and update any launch templates or Auto Scaling groups referencing ${ami.ImageId}`,
            },
          ));
        }
      }
    } catch (error) {
      logger.debug('Failed to check instances for outdated AMIs', { error: (error as Error).message });
    }

    return findings;
  }

  private async describeImagesByIds(imageIds: string[]): Promise<any[]> {
    const images: any[] = [];
    const BATCH_SIZE = 100;
    for (let i = 0; i < imageIds.length; i += BATCH_SIZE) {
      const batch = imageIds.slice(i, i + BATCH_SIZE);
      try {
        const result = await this.client.ec2.send(
          new DescribeImagesCommand({ ImageIds: batch, IncludeDeprecated: true }),
        );
        images.push(...(result.Images ?? []));
      } catch {
        // A stale AMI id fails the whole batch; fall back to one call per id
        for (const imageId of batch) {
          try {
            const result = await this.client.ec2.send(
              new DescribeImagesCommand({ ImageIds: [imageId], IncludeDeprecated: true }),
            );
            images.push(...(result.Images ?? []));
          } catch (error) {
            logger.debug(`Failed to describe AMI ${imageId}`, { error: (error as Error).message });
          }
        }
      }
    }
    return images;
  }

  // ── EBS volumes ──

  private async checkVolumes(volumes: any[], snapshots: any[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    if (volumes.length === 0) return findings;

    // ec2_ebs_volume_snapshots_exists
    const volumesWithSnapshots = new Set(snapshots.map((s) => s.VolumeId).filter(Boolean));
    for (const volume of volumes) {
      const volumeId = volume.VolumeId ?? 'Unknown';
      if (!volumesWithSnapshots.has(volumeId)) {
        findings.push(this.emit(
          'ec2_ebs_volume_snapshots_exists',
          { volumeId },
          {
            message: `No snapshots found for EBS volume "${volumeId}"`,
            remediation: `Create a snapshot of volume "${volumeId}" (aws ec2 create-snapshot --volume-id ${volumeId}) and automate snapshots with Data Lifecycle Manager or AWS Backup`,
          },
        ));
      }
    }

    // ec2_ebs_volume_protected_by_backup_plan
    try {
      const protectedArns = await this.getBackupProtectedResourceArns();
      const region = this.client.getRegion();
      const accountId = await this.client.getAccountId();
      const wildcardProtected = protectedArns.has('*') || protectedArns.has('arn:aws:ec2:*:*:volume/*');
      for (const volume of volumes) {
        const volumeId = volume.VolumeId ?? 'Unknown';
        const volumeArn = `arn:aws:ec2:${region}:${accountId}:volume/${volumeId}`;
        if (!wildcardProtected && !protectedArns.has(volumeArn)) {
          findings.push(this.emit(
            'ec2_ebs_volume_protected_by_backup_plan',
            { volumeId, volumeArn },
            {
              message: `EBS volume "${volumeId}" is not protected by any AWS Backup plan`,
              remediation: `Assign volume "${volumeId}" to an AWS Backup plan (directly or via a resource selection such as arn:aws:ec2:*:*:volume/*) aligned to your RPO/RTO`,
            },
          ));
        }
      }
    } catch (error) {
      logger.debug('Failed to check EBS volume backup plan protection', { error: (error as Error).message });
    }

    return findings;
  }

  // ── Elastic IPs ──

  private async checkElasticIps(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const result = await retry(async () =>
      this.client.ec2.send(new DescribeAddressesCommand({})),
    );
    for (const address of result.Addresses ?? []) {
      if (address.PublicIp && !address.AssociationId) {
        findings.push(this.emit(
          'ec2_elastic_ip_unassigned',
          { publicIp: address.PublicIp, allocationId: address.AllocationId ?? null },
          {
            message: `Elastic IP ${address.PublicIp} is not associated with any instance or network interface`,
            remediation: `Associate Elastic IP ${address.PublicIp} where required or release it: aws ec2 release-address --allocation-id ${address.AllocationId ?? '<allocation-id>'}`,
          },
        ));
      }
    }
    return findings;
  }

  // ── Client VPN endpoints ──

  private async checkClientVpnEndpoints(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () =>
        this.client.ec2.send(new DescribeClientVpnEndpointsCommand({ NextToken: nextToken })),
      );
      for (const endpoint of result.ClientVpnEndpoints ?? []) {
        const endpointId = endpoint.ClientVpnEndpointId ?? 'Unknown';
        if (!endpoint.ConnectionLogOptions?.Enabled) {
          findings.push(this.emit(
            'ec2_client_vpn_endpoint_connection_logging_enabled',
            { endpointId },
            {
              message: `Client VPN endpoint "${endpointId}" does not have client connection logging enabled`,
              remediation: `Enable connection logging: aws ec2 modify-client-vpn-endpoint --client-vpn-endpoint-id ${endpointId} --connection-log-options Enabled=true,CloudWatchLogGroup=<log-group>`,
            },
          ));
        }
      }
      nextToken = result.NextToken;
    } while (nextToken);
    return findings;
  }

  // ── Transit Gateways ──

  private async checkTransitGateways(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () =>
        this.client.ec2.send(new DescribeTransitGatewaysCommand({ NextToken: nextToken })),
      );
      for (const tgw of result.TransitGateways ?? []) {
        const tgwId = tgw.TransitGatewayId ?? 'Unknown';
        if (tgw.Options?.AutoAcceptSharedAttachments === 'enable') {
          findings.push(this.emit(
            'ec2_transitgateway_auto_accept_vpc_attachments',
            { tgwId, tgwArn: tgw.TransitGatewayArn ?? null },
            {
              message: `Transit Gateway "${tgwId}" is configured to automatically accept shared VPC attachments`,
              remediation: `Disable auto-accept so every cross-account attachment requires explicit approval: aws ec2 modify-transit-gateway --transit-gateway-id ${tgwId} --options AutoAcceptSharedAttachments=disable`,
            },
          ));
        }
      }
      nextToken = result.NextToken;
    } while (nextToken);
    return findings;
  }

  // ── Instance hygiene ──

  private checkInstanceHygiene(instances: any[]): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const now = Date.now();

    for (const instance of instances) {
      const instanceId = instance.InstanceId ?? 'Unknown';
      const state: string = instance.State?.Name ?? '';
      if (state === 'terminated') continue;

      // ec2_instance_profile_attached
      if (!instance.IamInstanceProfile) {
        findings.push(this.emit(
          'ec2_instance_profile_attached',
          { instanceId },
          {
            message: `EC2 Instance "${instanceId}" is not associated with an instance profile role`,
            remediation: `Attach a least-privilege IAM instance profile to instance "${instanceId}" so workloads use role credentials instead of static keys`,
          },
        ));
      }

      // ec2_instance_public_ip
      if (instance.PublicIpAddress) {
        findings.push(this.emit(
          'ec2_instance_public_ip',
          { instanceId, publicIp: instance.PublicIpAddress, publicDns: instance.PublicDnsName ?? null },
          {
            message: `EC2 Instance "${instanceId}" has a public IP: ${instance.PublicIpAddress}${instance.PublicDnsName ? ` (${instance.PublicDnsName})` : ''}`,
            remediation: `Remove the public IP from instance "${instanceId}": place it in a private subnet behind a load balancer or NAT and use Session Manager for administration`,
          },
        ));
      }

      // ec2_instance_internet_facing_with_instance_profile
      if (instance.PublicIpAddress && instance.IamInstanceProfile) {
        findings.push(this.emit(
          'ec2_instance_internet_facing_with_instance_profile',
          { instanceId, publicIp: instance.PublicIpAddress, instanceProfileArn: instance.IamInstanceProfile.Arn ?? null },
          {
            message: `EC2 Instance "${instanceId}" at IP ${instance.PublicIpAddress} is internet-facing with instance profile ${instance.IamInstanceProfile.Arn ?? 'attached'}`,
            remediation: `Remove the public exposure or the instance profile from "${instanceId}"; enforce IMDSv2 and least privilege on the role to limit credential-theft blast radius`,
          },
        ));
      }

      // ec2_instance_paravirtual_type
      if (instance.VirtualizationType === 'paravirtual') {
        findings.push(this.emit(
          'ec2_instance_paravirtual_type',
          { instanceId, virtualizationType: 'paravirtual' },
          {
            message: `EC2 Instance "${instanceId}" uses the paravirtual virtualization type`,
            remediation: `Migrate instance "${instanceId}" to an HVM-based AMI and a current instance family, then terminate the paravirtual instance`,
          },
        ));
      }

      // ec2_instance_older_than_specific_days (running instances only, as in Prowler)
      if (state === 'running' && instance.LaunchTime) {
        const days = Math.floor((now - new Date(instance.LaunchTime).getTime()) / 86_400_000);
        if (days > MAX_INSTANCE_AGE_DAYS) {
          findings.push(this.emit(
            'ec2_instance_older_than_specific_days',
            { instanceId, launchTime: instance.LaunchTime, ageDays: days, maxDays: MAX_INSTANCE_AGE_DAYS },
            {
              message: `EC2 Instance "${instanceId}" is older than ${MAX_INSTANCE_AGE_DAYS} days (${days} days)`,
              remediation: `Rebuild instance "${instanceId}" from a current hardened AMI or retire it; prefer short-lived, regularly rotated workloads`,
            },
          ));
        }
      }

      // ec2_instance_stopped_older_than_specific_days
      if (state === 'stopped') {
        const stopTime = parseStateTransitionTime(instance.StateTransitionReason);
        if (stopTime !== null) {
          const days = Math.floor((now - stopTime) / 86_400_000);
          if (days > MAX_INSTANCE_STOPPED_DAYS) {
            findings.push(this.emit(
              'ec2_instance_stopped_older_than_specific_days',
              { instanceId, stoppedDays: days, maxDays: MAX_INSTANCE_STOPPED_DAYS, stateTransitionReason: instance.StateTransitionReason },
              {
                message: `EC2 Instance "${instanceId}" has been stopped longer than ${MAX_INSTANCE_STOPPED_DAYS} days (${days} days)`,
                remediation: `Terminate instance "${instanceId}" if no longer needed, or start and patch it and return it to an actively managed lifecycle`,
              },
            ));
          }
        }
      }

      // ec2_instance_uses_single_eni
      const countedEnis = (instance.NetworkInterfaces ?? []).filter((eni: any) =>
        ['efa', 'interface', 'trunk'].includes(eni.InterfaceType ?? 'interface'),
      );
      if (countedEnis.length > 1) {
        const eniIds = countedEnis.map((eni: any) => eni.NetworkInterfaceId).filter(Boolean);
        findings.push(this.emit(
          'ec2_instance_uses_single_eni',
          { instanceId, eniIds },
          {
            message: `EC2 Instance "${instanceId}" uses multiple ENIs: ${eniIds.join(', ')}`,
            remediation: `Detach the secondary network interfaces from instance "${instanceId}" unless multi-homing is formally approved; use gateways or load balancers instead of dual-homed hosts`,
          },
        ));
      }
    }

    return findings;
  }

  // ── Instance service-port exposure (table-driven family) ──

  private checkInstancePortExposure(
    instances: any[],
    sgById: Map<string, any>,
    isPublicSubnet: (subnetId: string, vpcId: string) => boolean,
  ): ScanningResult[] {
    const findings: ScanningResult[] = [];

    for (const instance of instances) {
      const instanceId = instance.InstanceId ?? 'Unknown';
      const attachedSgs = (instance.SecurityGroups ?? [])
        .map((sg: any) => sgById.get(sg.GroupId ?? ''))
        .filter(Boolean);
      if (attachedSgs.length === 0) continue;

      for (const check of INSTANCE_PORT_CHECKS) {
        const openSg = attachedSgs.find((sg: any) =>
          (sg.IpPermissions ?? []).some(
            (rule: any) => ruleOpenToInternet(rule) && ruleMatchesTcpPorts(rule, check.ports),
          ),
        );
        if (!openSg) continue;

        const publicSubnet = isPublicSubnet(instance.SubnetId ?? '', instance.VpcId ?? '');
        const exposure = instanceExposure(instance, publicSubnet);
        findings.push(this.emit(
          check.checkId,
          {
            instanceId,
            service: check.label,
            ports: check.ports,
            sgId: openSg.GroupId,
            sgName: openSg.GroupName,
            publicIp: instance.PublicIpAddress ?? null,
            subnetId: instance.SubnetId ?? null,
            publicSubnet,
          },
          {
            message: `Instance "${instanceId}" has ${check.label} ports (${check.ports.join(', ')}) open to the Internet via security group "${openSg.GroupName}" (${openSg.GroupId})${exposure.detail}`,
            remediation: `Remove the 0.0.0.0/0 and ::/0 ingress for ${check.label} ports ${check.ports.join(', ')} in security group "${openSg.GroupName}" (${openSg.GroupId}) and restrict access to trusted CIDRs or peer security groups`,
            severity: exposure.severity,
          },
        ));
      }
    }
    return findings;
  }

  // ── Confidential-workload (Nitro Enclave) hosts ──

  private checkConfidentialWorkloadHosts(
    instances: any[],
    sgById: Map<string, any>,
    isPublicSubnet: (subnetId: string, vpcId: string) => boolean,
  ): ScanningResult[] {
    const findings: ScanningResult[] = [];

    for (const instance of instances) {
      if (!instance.EnclaveOptions?.Enabled) continue;
      const instanceId = instance.InstanceId ?? 'Unknown';
      const state: string = instance.State?.Name ?? '';

      // ec2_confidential_workload_host_not_running (evaluates every enclave-enabled instance)
      if (ENCLAVE_TERMINAL_STATES.has(state)) {
        findings.push(this.emit(
          'ec2_confidential_workload_host_not_running',
          { instanceId, state },
          {
            message: `Nitro Enclave parent instance "${instanceId}" is in state "${state}"; enclaves are destroyed when the parent stops`,
            remediation: `Start instance "${instanceId}" and relaunch the enclave (nitro-cli run-enclave), or decommission any downstream dependency on its enclave availability`,
          },
        ));
        continue; // remaining host checks only apply to active hosts (Prowler is_enclave_parent)
      }

      // ec2_confidential_workload_host_imdsv2_not_enforced
      if (instance.MetadataOptions?.HttpTokens !== 'required') {
        findings.push(this.emit(
          'ec2_confidential_workload_host_imdsv2_not_enforced',
          { instanceId, httpTokens: instance.MetadataOptions?.HttpTokens ?? null },
          {
            message: `Confidential-workload host "${instanceId}" does not enforce IMDSv2 (HttpTokens=${instance.MetadataOptions?.HttpTokens ?? 'unset'})`,
            remediation: `Enforce IMDSv2 on host "${instanceId}": aws ec2 modify-instance-metadata-options --instance-id ${instanceId} --http-tokens required --http-endpoint enabled`,
          },
        ));
      }

      // ec2_confidential_workload_host_public_ip
      const globalIpv6: string[] = [];
      for (const eni of instance.NetworkInterfaces ?? []) {
        for (const ipv6 of eni.Ipv6Addresses ?? []) {
          if (ipv6.Ipv6Address && isGlobalIpv6(ipv6.Ipv6Address)) globalIpv6.push(ipv6.Ipv6Address);
        }
      }
      const publicSubnet = isPublicSubnet(instance.SubnetId ?? '', instance.VpcId ?? '');
      if (instance.PublicIpAddress || globalIpv6.length > 0 || publicSubnet) {
        const reasons: string[] = [];
        if (instance.PublicIpAddress) reasons.push(`public IPv4 ${instance.PublicIpAddress}`);
        if (globalIpv6.length > 0) reasons.push(`global IPv6 on its ENIs (${globalIpv6.join(', ')})`);
        if (publicSubnet) reasons.push('its subnet routes 0.0.0.0/0 or ::/0 to an internet gateway');
        findings.push(this.emit(
          'ec2_confidential_workload_host_public_ip',
          { instanceId, publicIp: instance.PublicIpAddress ?? null, globalIpv6, publicSubnet },
          {
            message: `Confidential-workload host "${instanceId}" is internet-exposed: ${reasons.join(' and ')}`,
            remediation: `Move host "${instanceId}" to a private subnet, remove its public/Elastic IP, and route required egress through a NAT gateway`,
          },
        ));
      }

      const attachedSgs = (instance.SecurityGroups ?? [])
        .map((sg: any) => sgById.get(sg.GroupId ?? ''))
        .filter(Boolean);

      // ec2_confidential_workload_host_unrestricted_ingress
      const exposedPorts = new Set<string>();
      for (const sg of attachedSgs) {
        for (const rule of sg.IpPermissions ?? []) {
          const portRange = worldFacingPortRange(rule, ['tcp', 'udp']);
          if (portRange === null) continue;
          if (portRange === 'all') {
            exposedPorts.add('all');
            continue;
          }
          const [from, to] = portRange;
          const allowedInRange = [...ENCLAVE_ALLOWED_PORTS].filter((p) => p >= from && p <= to).length;
          const nonAllowedCount = to - from + 1 - allowedInRange;
          if (nonAllowedCount <= 0) continue;
          if (nonAllowedCount > ENCLAVE_INGRESS_SUMMARY_THRESHOLD) {
            exposedPorts.add(`${from}-${to}`);
          } else {
            for (let port = from; port <= to; port++) {
              if (!ENCLAVE_ALLOWED_PORTS.has(port)) exposedPorts.add(String(port));
            }
          }
        }
      }
      if (exposedPorts.size > 0) {
        const portsList = [...exposedPorts].sort().join(', ');
        findings.push(this.emit(
          'ec2_confidential_workload_host_unrestricted_ingress',
          { instanceId, exposedPorts: [...exposedPorts] },
          {
            message: `Confidential-workload host "${instanceId}" has security groups exposing non-allow-listed ports to the internet: ${portsList}`,
            remediation: `Restrict internet ingress on host "${instanceId}" to ports ${[...ENCLAVE_ALLOWED_PORTS].join(', ')} at most; source other ports from private CIDRs or peer security groups`,
          },
        ));
      }

      // ec2_confidential_workload_host_vsock_proxy_exposed
      const exposedVsock = new Set<number>();
      for (const sg of attachedSgs) {
        for (const rule of sg.IpPermissions ?? []) {
          const portRange = worldFacingPortRange(rule, ['tcp']);
          if (portRange === null) continue;
          if (portRange === 'all') {
            VSOCK_PORTS.forEach((port) => exposedVsock.add(port));
            continue;
          }
          const [from, to] = portRange;
          for (const port of VSOCK_PORTS) {
            if (port >= from && port <= to) exposedVsock.add(port);
          }
        }
      }
      if (exposedVsock.size > 0) {
        const portsList = [...exposedVsock].sort((a, b) => a - b).join(', ');
        findings.push(this.emit(
          'ec2_confidential_workload_host_vsock_proxy_exposed',
          { instanceId, exposedPorts: [...exposedVsock].sort((a, b) => a - b) },
          {
            message: `Confidential-workload host "${instanceId}" exposes likely vsock-proxy TCP ports to the internet: ${portsList} (heuristic; verify against the actual proxy scheme)`,
            remediation: `Restrict the vsock-proxy TCP ports on host "${instanceId}" to internal CIDRs or peer security groups only`,
          },
        ));
      }
    }

    return findings;
  }

  // ── Security group rule checks (table-driven family + singletons) ──

  private checkSecurityGroupRules(securityGroups: any[], enisBySg: Map<string, any[]>): ScanningResult[] {
    const findings: ScanningResult[] = [];

    const referencedSgIds = new Set<string>();
    for (const sg of securityGroups) {
      for (const rule of sg.IpPermissions ?? []) {
        for (const pair of rule.UserIdGroupPairs ?? []) {
          if (pair.GroupId) referencedSgIds.add(pair.GroupId);
        }
      }
    }

    for (const sg of securityGroups) {
      const sgId: string = sg.GroupId ?? 'Unknown';
      const sgName: string = sg.GroupName ?? sgId;
      const enis = enisBySg.get(sgId) ?? [];
      const ingressRules: any[] = sg.IpPermissions ?? [];
      const egressRules: any[] = sg.IpPermissionsEgress ?? [];

      // ec2_securitygroup_from_launch_wizard
      if (sgName.includes('launch-wizard')) {
        findings.push(this.emit(
          'ec2_securitygroup_from_launch_wizard',
          { sgId, sgName },
          {
            message: `Security group "${sgName}" (${sgId}) was created by the EC2 Launch Wizard and may contain overly permissive defaults`,
            remediation: `Replace security group "${sgName}" with a curated baseline group, then delete it: aws ec2 delete-security-group --group-id ${sgId}`,
          },
        ));
      }

      // ec2_securitygroup_with_many_ingress_egress_rules
      if (ingressRules.length > MAX_SG_RULES || egressRules.length > MAX_SG_RULES) {
        findings.push(this.emit(
          'ec2_securitygroup_with_many_ingress_egress_rules',
          { sgId, sgName, ingressRuleCount: ingressRules.length, egressRuleCount: egressRules.length },
          {
            message: `Security group "${sgName}" (${sgId}) has ${ingressRules.length} inbound and ${egressRules.length} outbound rules, exceeding the recommended maximum of ${MAX_SG_RULES}`,
            remediation: `Split security group "${sgName}" into role-specific groups, deduplicate rules, and remove stale entries until each direction has at most ${MAX_SG_RULES} rules`,
          },
        ));
      }

      // ec2_securitygroup_not_used (default SGs cannot be deleted; Lambda usage
      // is covered indirectly because VPC-attached Lambdas keep ENIs)
      if (sgName !== 'default' && enis.length === 0 && !referencedSgIds.has(sgId)) {
        findings.push(this.emit(
          'ec2_securitygroup_not_used',
          { sgId, sgName },
          {
            message: `Security group "${sgName}" (${sgId}) is not attached to any network interface and is not referenced by other security groups`,
            remediation: `Delete unused security group "${sgName}": aws ec2 delete-security-group --group-id ${sgId}`,
          },
        ));
      }

      // Remaining ingress checks only evaluate security groups in use (Prowler parity)
      if (enis.length === 0) continue;

      // ec2_securitygroup_allow_wide_open_public_ipv4 (ingress + egress)
      const wideOpen = findWideOpenPublicCidr(ingressRules, 'ingress') ?? findWideOpenPublicCidr(egressRules, 'egress');
      if (wideOpen) {
        findings.push(this.emit(
          'ec2_securitygroup_allow_wide_open_public_ipv4',
          { sgId, sgName, cidr: wideOpen.cidr, direction: wideOpen.direction },
          {
            message: `Security group "${sgName}" (${sgId}) has wide-open public IPv4 range ${wideOpen.cidr} in an ${wideOpen.direction} rule`,
            remediation: `Replace ${wideOpen.cidr} in security group "${sgName}" with specific /24-or-narrower public CIDRs or private RFC1918 ranges`,
          },
        ));
      }

      // ec2_securitygroup_allow_ingress_from_internet_to_all_ports
      const allPortsOpen = ingressRules.some((rule) =>
        ruleOpenToInternet(rule) &&
        (rule.IpProtocol === '-1' ||
          (rule.FromPort !== undefined && rule.ToPort !== undefined && rule.FromPort <= 0 && rule.ToPort >= 65535)));

      if (allPortsOpen) {
        findings.push(this.emit(
          'ec2_securitygroup_allow_ingress_from_internet_to_all_ports',
          { sgId, sgName },
          {
            message: `Security group "${sgName}" (${sgId}) has all ports open to the Internet`,
            remediation: `Delete the all-traffic ingress rule from 0.0.0.0/0 (or ::/0) in security group "${sgName}" (${sgId}) and allow only the specific ports and sources the workload needs`,
          },
        ));
        continue; // per-port and any-port checks are skipped when all ports already failed (Prowler parity)
      }

      // ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_* family
      for (const check of SG_PORT_CHECKS) {
        const open = ingressRules.some(
          (rule) => ruleOpenToInternet(rule) && ruleMatchesTcpPorts(rule, check.ports),
        );
        if (open) {
          findings.push(this.emit(
            check.checkId,
            { sgId, sgName, ports: check.ports },
            {
              message: `Security group "${sgName}" (${sgId}) has ${check.label} open to the Internet`,
              remediation: `Remove the 0.0.0.0/0 and ::/0 ingress rules for ${check.label} in security group "${sgName}" (${sgId}) and allow only trusted CIDRs or peer security groups`,
            },
          ));
        }
      }

      // ec2_securitygroup_allow_ingress_from_internet_to_any_port
      if (ingressRules.some((rule) => ruleOpenToInternet(rule))) {
        const offendingEni = enis.find((eni: any) =>
          !SG_ALLOWED_ENI_TYPES.has(eni.InterfaceType ?? '') &&
          !SG_ALLOWED_INSTANCE_OWNERS.has(eni.Attachment?.InstanceOwnerId ?? ''));
        if (offendingEni) {
          findings.push(this.emit(
            'ec2_securitygroup_allow_ingress_from_internet_to_any_port',
            { sgId, sgName, eniId: offendingEni.NetworkInterfaceId, eniType: offendingEni.InterfaceType ?? null },
            {
              message: `Security group "${sgName}" (${sgId}) has at least one port open to the Internet and is attached to network interface ${offendingEni.NetworkInterfaceId} (type "${offendingEni.InterfaceType ?? 'unknown'}"), which is not an approved public-facing interface`,
              remediation: `Remove the 0.0.0.0/0 and ::/0 ingress rules from security group "${sgName}" (${sgId}) or move public exposure behind a load balancer, API gateway or VPC endpoint`,
            },
          ));
        }
      }

      // ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip
      const specificPublicSource = findSpecificPublicSource(ingressRules);
      if (specificPublicSource) {
        findings.push(this.emit(
          'ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip',
          { sgId, sgName, source: specificPublicSource },
          {
            message: `Security group "${sgName}" (${sgId}) allows ingress from specific public IP source ${specificPublicSource}`,
            remediation: `Review the ingress rule for ${specificPublicSource} in security group "${sgName}" (${sgId}); remove stale personal or third-party IP allowlists and use VPN, Session Manager or PrivateLink instead`,
          },
        ));
      }
    }

    return findings;
  }

  // ── Network ACLs ──

  private async checkNetworkAclRules(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const nacls = await this.getAllNetworkAcls();

    for (const nacl of nacls) {
      const naclId: string = nacl.NetworkAclId ?? 'Unknown';
      const naclName: string =
        (nacl.Tags ?? []).find((tag: any) => tag.Key === 'Name')?.Value ?? naclId;

      // ec2_networkacl_allow_ingress_tcp_port_22 / _3389
      for (const check of NACL_PORT_CHECKS) {
        if (naclAllowsIngressTcpPort(nacl.Entries ?? [], check.port)) {
          findings.push(this.emit(
            check.checkId,
            { naclId, naclName, port: check.port },
            {
              message: `Network ACL "${naclName}" (${naclId}) allows ingress from the Internet to ${check.label} port ${check.port}`,
              remediation: `Remove or deny the allow entry for TCP port ${check.port} from 0.0.0.0/0 (and ::/0) in network ACL ${naclId}`,
            },
          ));
        }
      }

      // ec2_networkacl_unused
      const inUse = (nacl.Associations ?? []).some((assoc: any) => assoc.SubnetId);
      if (nacl.IsDefault !== true && !inUse) {
        findings.push(this.emit(
          'ec2_networkacl_unused',
          { naclId, naclName },
          {
            message: `Network ACL "${naclName}" (${naclId}) is not associated with any subnet and is not the default network ACL`,
            remediation: `Delete unused network ACL ${naclId} (aws ec2 delete-network-acl --network-acl-id ${naclId}) or associate it with the intended subnets`,
          },
        ));
      }
    }

    return findings;
  }

  // ── Launch templates ──

  private async checkLaunchTemplates(eniById: Map<string, any>): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const templates = await this.getAllLaunchTemplates();

    for (const template of templates) {
      const templateId: string = template.LaunchTemplateId ?? '';
      const templateName: string = template.LaunchTemplateName ?? templateId;
      if (!templateId) continue;

      let versions: any[] = [];
      try {
        versions = await this.getLaunchTemplateVersions(templateId);
      } catch (error) {
        logger.debug(`Failed to describe launch template versions for ${templateName}`, { error: (error as Error).message });
        continue;
      }
      if (versions.length === 0) continue;

      // ec2_launch_template_imdsv2_required
      const imdsv2Versions: string[] = [];
      const metadataDisabledVersions: string[] = [];
      const noImdsv2Versions: string[] = [];
      for (const version of versions) {
        const metadata = version.LaunchTemplateData?.MetadataOptions ?? {};
        const httpEndpoint: string = metadata.HttpEndpoint ?? '';
        const httpTokens: string = metadata.HttpTokens ?? '';
        const versionNumber = String(version.VersionNumber ?? '');
        if (httpEndpoint === 'enabled' && httpTokens === 'required') {
          imdsv2Versions.push(versionNumber);
        } else if (httpEndpoint === 'disabled' || !httpEndpoint) {
          metadataDisabledVersions.push(versionNumber);
        } else {
          noImdsv2Versions.push(versionNumber);
        }
      }
      if (imdsv2Versions.length === 0 && metadataDisabledVersions.length === 0) {
        findings.push(this.emit(
          'ec2_launch_template_imdsv2_required',
          { templateId, templateName, versionsWithoutImdsv2: noImdsv2Versions },
          {
            message: `EC2 Launch Template "${templateName}" has IMDSv2 disabled or not required in versions: ${noImdsv2Versions.join(', ')}`,
            remediation: `Create a new version of launch template "${templateName}" with MetadataOptions HttpTokens=required (or metadata disabled) and set it as the default version`,
          },
        ));
      }

      // ec2_launch_template_no_public_ip
      const autoAssignVersions: string[] = [];
      const publicEniVersions: string[] = [];
      for (const version of versions) {
        const versionNumber = String(version.VersionNumber ?? '');
        const templateEnis: any[] = version.LaunchTemplateData?.NetworkInterfaces ?? [];
        if (templateEnis.some((eni: any) => eni.AssociatePublicIpAddress === true)) {
          autoAssignVersions.push(versionNumber);
        }
        if (templateEnis.some((eni: any) => {
          const existing = eni.NetworkInterfaceId ? eniById.get(eni.NetworkInterfaceId) : undefined;
          return existing !== undefined && eniHasPublicIp(existing);
        })) {
          publicEniVersions.push(versionNumber);
        }
      }
      if (autoAssignVersions.length > 0 || publicEniVersions.length > 0) {
        const details: string[] = [];
        if (autoAssignVersions.length > 0) {
          details.push(`auto-assigns a public IP in versions ${autoAssignVersions.join(', ')}`);
        }
        if (publicEniVersions.length > 0) {
          details.push(`references a network interface with a public IP in versions ${publicEniVersions.join(', ')}`);
        }
        findings.push(this.emit(
          'ec2_launch_template_no_public_ip',
          { templateId, templateName, autoAssignVersions, publicEniVersions },
          {
            message: `EC2 Launch Template "${templateName}" ${details.join(' and ')}`,
            remediation: `Create a new version of launch template "${templateName}" with AssociatePublicIpAddress=false and no public-IP network interfaces, and set it as the default version`,
          },
        ));
      }

      // ec2_launch_template_no_secrets
      const versionsWithSecrets: string[] = [];
      const secretTypes = new Set<string>();
      for (const version of versions) {
        const userData: string = version.LaunchTemplateData?.UserData ?? '';
        if (!userData) continue;
        const decoded = decodeUserData(userData);
        if (decoded === null) {
          logger.debug(`Unable to decode user data for launch template ${templateName} version ${version.VersionNumber}`);
          continue;
        }
        const secrets = findSecretsInText(decoded);
        if (secrets.length > 0) {
          versionsWithSecrets.push(String(version.VersionNumber ?? ''));
          secrets.forEach((secret) => secretTypes.add(secret));
        }
      }
      if (versionsWithSecrets.length > 0) {
        findings.push(this.emit(
          'ec2_launch_template_no_secrets',
          { templateId, templateName, versionsWithSecrets, secretTypes: [...secretTypes] },
          {
            message: `Potential secret found in User Data of EC2 Launch Template "${templateName}" versions: ${versionsWithSecrets.join(', ')} (${[...secretTypes].join(', ')})`,
            remediation: `Create a clean version of launch template "${templateName}" without secrets in User Data, delete the affected versions, and rotate any exposed credentials`,
          },
        ));
      }
    }

    return findings;
  }

  // ── Instance user data secrets ──

  private async checkInstanceUserDataSecrets(instances: any[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    for (const instance of instances) {
      const state: string = instance.State?.Name ?? '';
      if (state === 'terminated') continue;
      const instanceId: string = instance.InstanceId ?? '';
      if (!instanceId) continue;

      try {
        const result = await retry(async () =>
          this.client.ec2.send(
            new DescribeInstanceAttributeCommand({ Attribute: 'userData', InstanceId: instanceId }),
          ),
        );
        const userData = result.UserData?.Value;
        if (!userData) continue;
        const decoded = decodeUserData(userData);
        if (decoded === null) {
          logger.debug(`Unable to decode user data for EC2 instance ${instanceId}`);
          continue;
        }
        const secrets = findSecretsInText(decoded);
        if (secrets.length > 0) {
          findings.push(this.emit(
            'ec2_instance_secrets_user_data',
            { instanceId, secretTypes: secrets },
            {
              message: `Potential secret found in EC2 instance "${instanceId}" User Data (${secrets.join(', ')})`,
              remediation: `Remove secrets from the User Data of instance "${instanceId}"; fetch them at runtime from Secrets Manager or SSM Parameter Store and rotate any exposed credentials`,
            },
          ));
        }
      } catch (error) {
        logger.debug(`Failed to check user data for EC2 instance ${instanceId}`, { error: (error as Error).message });
      }
    }

    return findings;
  }
}

export default EC2Scanner;
