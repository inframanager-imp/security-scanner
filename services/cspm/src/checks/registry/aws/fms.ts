// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const fmsChecks: CheckMetadata[] = [
  {
    checkId: 'fms_policy_compliant',
    provider: 'aws',
    service: 'fms',
    title: 'FMS Policy Non-Compliant or Missing',
    severity: 'MEDIUM',
    description: 'Checks that the Firewall Manager administrator account has security policies and that every member account is compliant with them; non-compliant or unevaluated accounts and missing policies are flagged.',
    remediation: 'From the Firewall Manager administrator account, create security policies scoped to all accounts with automatic remediation enabled, ensure AWS Config records all accounts and regions, and resolve any accounts reported as non-compliant.',
    tags: ['fms', 'firewall-manager', 'governance', 'compliance'],
  },
];
