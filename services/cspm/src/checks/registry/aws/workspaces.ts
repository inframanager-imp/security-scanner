// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const workspacesChecks: CheckMetadata[] = [
  {
    checkId: 'workspaces_volume_encryption_enabled',
    provider: 'aws',
    service: 'workspaces',
    title: 'WorkSpaces Volumes Not Encrypted',
    severity: 'HIGH',
    description: 'Checks that both the root and user volumes of each WorkSpace are encrypted at rest.',
    remediation: 'Volume encryption can only be set at creation time: rebuild the WorkSpace with root and user volume encryption enabled using a KMS key, then migrate user data.',
    tags: ['workspaces', 'encryption', 'kms'],
  },
  {
    checkId: 'workspaces_vpc_2private_1public_subnets_nat',
    provider: 'aws',
    service: 'workspaces',
    title: 'WorkSpaces Not in Recommended VPC Topology',
    severity: 'HIGH',
    description: 'Checks that each WorkSpace runs in a private subnet within a VPC that has at least 1 public subnet and 2 private subnets with a NAT Gateway, so desktops are not directly reachable from the Internet.',
    remediation: 'Deploy WorkSpaces into private subnets of a VPC with at least two private subnets and one public subnet, routing outbound traffic from the private subnets through a NAT Gateway.',
    tags: ['workspaces', 'network', 'vpc'],
  },
];
