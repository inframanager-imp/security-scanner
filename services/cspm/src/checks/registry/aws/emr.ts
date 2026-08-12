// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const emrChecks: CheckMetadata[] = [
  {
    checkId: 'emr_cluster_account_public_block_enabled',
    provider: 'aws',
    service: 'emr',
    title: 'EMR Block Public Access Disabled',
    severity: 'HIGH',
    description: 'Checks that the account-level EMR Block Public Access configuration is enabled, preventing creation of clusters whose security groups allow inbound traffic from the Internet.',
    remediation: 'Enable EMR Block Public Access (BlockPublicSecurityGroupRules=true) in every region in use so cluster creation is blocked when a security group allows inbound traffic from 0.0.0.0/0 on non-excepted ports.',
    tags: ['emr', 'public-access', 'account-setting'],
  },
  {
    checkId: 'emr_cluster_master_nodes_no_public_ip',
    provider: 'aws',
    service: 'emr',
    title: 'EMR Master Node Has Public IP',
    severity: 'MEDIUM',
    description: 'Checks that active EMR cluster master nodes are not reachable via public DNS/IP addresses; clusters should run in private subnets.',
    remediation: 'Launch EMR clusters into private subnets so master and core nodes receive only private addresses, and access them through VPN, Direct Connect or bastion hosts.',
    tags: ['emr', 'public-ip', 'network'],
  },
  {
    checkId: 'emr_cluster_publicly_accesible',
    provider: 'aws',
    service: 'emr',
    title: 'EMR Cluster Publicly Accessible',
    severity: 'MEDIUM',
    description: 'Checks that EMR clusters with public master DNS names do not have master or worker security groups permitting unrestricted ingress from public networks.',
    remediation: 'Restrict master and worker security group ingress to trusted CIDR ranges and required ports only; remove all-traffic or all-port rules open to public addresses and prefer private subnets.',
    tags: ['emr', 'public-access', 'security-group'],
  },
];
