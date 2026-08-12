// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const inspector2Checks: CheckMetadata[] = [
  {
    checkId: 'inspector2_is_enabled',
    provider: 'aws',
    service: 'inspector2',
    title: 'Inspector2 Not Fully Enabled',
    severity: 'MEDIUM',
    description: 'Checks that Amazon Inspector2 is enabled in the account and covering EC2 instances, ECR container images, Lambda functions and Lambda code where those resources exist in the region.',
    remediation: 'Enable Inspector2 for all applicable resource types: aws inspector2 enable --resource-types EC2 ECR LAMBDA LAMBDA_CODE --account-ids <account-id>.',
    tags: ['inspector2', 'vulnerability-management', 'scanning'],
  },
  {
    checkId: 'inspector2_active_findings_exist',
    provider: 'aws',
    service: 'inspector2',
    title: 'Inspector2 Active Findings Present',
    severity: 'HIGH',
    description: 'Checks that Inspector2 has no active vulnerability findings; active findings indicate unremediated vulnerabilities in EC2, ECR or Lambda workloads.',
    remediation: 'Review active Inspector2 findings, patch or rebuild the affected resources, and close or suppress findings once remediated.',
    tags: ['inspector2', 'vulnerability-management', 'findings'],
  },
];
