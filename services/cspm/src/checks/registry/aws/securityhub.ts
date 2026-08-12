// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const securityhubChecks: CheckMetadata[] = [
  {
    checkId: 'securityhub_enabled',
    provider: 'aws',
    service: 'securityhub',
    title: 'Security Hub Not Enabled or Without Standards',
    severity: 'HIGH',
    description: 'Checks that AWS Security Hub is enabled in the region with at least one security standard or product integration active, providing centralized security finding aggregation.',
    remediation: 'Enable Security Hub in the region (aws securityhub enable-security-hub) and enable at least one standard such as AWS Foundational Security Best Practices, or configure product integrations.',
    tags: ['securityhub', 'detection', 'monitoring'],
  },
  {
    checkId: 'securityhub_delegated_admin_enabled_all_regions',
    provider: 'aws',
    service: 'securityhub',
    title: 'Security Hub Delegated Admin Not Fully Configured',
    severity: 'HIGH',
    description: 'Checks that Security Hub has an enabled delegated administrator account for the organization, is active in the region, and auto-enables Security Hub for new organization member accounts.',
    remediation: 'From the organization management account, register a delegated Security Hub administrator (aws securityhub enable-organization-admin-account), enable Security Hub in all used regions, and turn on organization auto-enable.',
    tags: ['securityhub', 'organizations', 'delegated-admin'],
  },
];
