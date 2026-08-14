// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const policyChecks: CheckMetadata[] = [
  {
    checkId: 'policy_ensure_asc_enforcement_enabled',
    provider: 'azure',
    service: 'policy',
    title: 'Defender For Cloud Default Policy Assignment Is Enforced',
    severity: 'MEDIUM',
    description: 'Checks that the Defender for Cloud built-in policy assignment (SecurityCenterBuiltIn) has enforcement mode set to Default rather than DoNotEnforce, so policy effects like deny and deployIfNotExists are actually applied.',
    remediation: 'Set the enforcement mode of the "SecurityCenterBuiltIn" policy assignment back to Default so its effects are enforced. Use time-bound policy exemptions for justified exceptions instead of disabling enforcement.',
    tags: ['policy', 'governance', 'defender-for-cloud'],
  },
];
