// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const trustedadvisorChecks: CheckMetadata[] = [
  {
    checkId: 'trustedadvisor_errors_and_warnings',
    provider: 'aws',
    service: 'trustedadvisor',
    title: 'Trusted Advisor Check Reporting Errors or Warnings',
    severity: 'MEDIUM',
    description: 'Checks that AWS Trusted Advisor checks (security, fault tolerance, service limits, cost) are not reporting error or warning states that indicate misconfigurations or exhausted quotas.',
    remediation: 'Open Trusted Advisor, filter checks by Warning and Error status, apply the recommended actions for each affected resource, then refresh the check until it reports OK.',
    tags: ['trustedadvisor', 'monitoring', 'best-practices'],
  },
];
