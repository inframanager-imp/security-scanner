import { CheckMetadata } from '../../types';

// Titles must stay byte-identical to the pre-registry hardcoded titles:
// the scan worker dedupes OPEN findings on service:title:fingerprint, so a
// reworded title would re-open every existing finding as "new".
export const vpcChecks: CheckMetadata[] = [
  {
    checkId: 'vpc_default_vpc_exists',
    provider: 'aws',
    service: 'vpc',
    title: 'Default VPC Exists',
    severity: 'LOW',
    description: 'Checks for the presence of a default VPC, which ships with an internet route, default security group, and default ACL that resources launched into it inherit.',
    remediation: 'Delete the default VPC if unused, or replace it with a custom VPC. Always launch workloads into a custom VPC.',
    tags: ['vpc', 'default-vpc', 'cis-5.1'],
    compliance: {
      cis_2_0_aws: ['5.1'],
    },
  },
  {
    checkId: 'ec2_securitygroup_default_restrict_traffic',
    provider: 'aws',
    service: 'vpc',
    title: 'Default Security Group Not Restricted',
    severity: 'MEDIUM',
    description: 'Checks that the default security group of every VPC restricts all traffic (no inbound rules and no non-default outbound rules).',
    remediation: 'Remove all inbound and outbound rules from the default security group in each VPC',
    tags: ['vpc', 'security-group', 'cis-5.3'],
    compliance: {
      cis_2_0_aws: ['5.3'],
    },
  },
  {
    checkId: 'vpc_peering_routing_tables_with_least_privilege',
    provider: 'aws',
    service: 'vpc',
    title: 'VPC Peering Route Not Least Access',
    severity: 'MEDIUM',
    description: 'Checks route tables for overly broad routes (/0 destinations) pointing to VPC peering connections, which violate least-privilege network access.',
    remediation: 'Review VPC peering routes and restrict to only the specific CIDR blocks that are required',
    tags: ['vpc', 'peering', 'routing', 'cis-5.4'],
    compliance: {
      cis_2_0_aws: ['5.4'],
    },
  },
  {
    checkId: 'vpc_ebs_default_encryption_disabled',
    provider: 'aws',
    service: 'vpc',
    title: 'EBS Default Encryption Not Enabled',
    severity: 'MEDIUM',
    description: 'Checks that EBS default encryption is enabled so new EBS volumes are automatically encrypted at rest.',
    remediation: 'Enable EBS default encryption in the EC2 console to automatically encrypt all new EBS volumes',
    tags: ['ec2', 'ebs', 'encryption', 'cis-2.2.1'],
    compliance: {
      cis_2_0_aws: ['2.2.1'],
    },
  },
];
