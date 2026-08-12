// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const storagegatewayChecks: CheckMetadata[] = [
  {
    checkId: 'storagegateway_fileshare_encryption_enabled',
    provider: 'aws',
    service: 'storagegateway',
    title: 'Storage Gateway File Share Not KMS Encrypted',
    severity: 'MEDIUM',
    description: 'Checks that Storage Gateway NFS and SMB file shares encrypt their data with a KMS customer managed key instead of the default S3-managed encryption.',
    remediation: 'Enable KMSEncrypted with a customer managed KMS key on the file share, and apply least-privilege key policies for the roles that read and write the share.',
    tags: ['storagegateway', 'encryption', 'kms'],
  },
  {
    checkId: 'storagegateway_gateway_fault_tolerant',
    provider: 'aws',
    service: 'storagegateway',
    title: 'Storage Gateway Hosted on Single EC2 Instance',
    severity: 'MEDIUM',
    description: 'Checks that Storage Gateway gateways are not hosted on a single EC2 instance, which is a single point of failure without high-availability support.',
    remediation: 'Host the gateway on a platform with fault tolerance (for example a VMware HA-enabled environment or a hardware appliance), or design recovery procedures for EC2-hosted gateways.',
    tags: ['storagegateway', 'resilience', 'availability'],
  },
];
