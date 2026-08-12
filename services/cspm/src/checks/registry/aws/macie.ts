// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const macieChecks: CheckMetadata[] = [
  {
    checkId: 'macie_is_enabled',
    provider: 'aws',
    service: 'macie',
    title: 'Macie Not Enabled',
    severity: 'MEDIUM',
    description: 'Checks that Amazon Macie is enabled (and not suspended) in the region when the account stores data in S3, so sensitive data exposure can be discovered.',
    remediation: 'Enable Amazon Macie in the region (aws macie2 enable-macie). If Macie is suspended, re-enable it so sensitive data discovery and S3 security evaluation resume.',
    tags: ['macie', 'data-protection', 's3'],
  },
  {
    checkId: 'macie_automated_sensitive_data_discovery_enabled',
    provider: 'aws',
    service: 'macie',
    title: 'Macie Automated Sensitive Data Discovery Disabled',
    severity: 'HIGH',
    description: 'Checks that Macie has automated sensitive data discovery enabled so S3 buckets are continually sampled for sensitive data instead of relying on one-off classification jobs.',
    remediation: 'Enable automated sensitive data discovery: aws macie2 update-automated-discovery-configuration --status ENABLED.',
    tags: ['macie', 'data-protection', 'discovery'],
  },
];
