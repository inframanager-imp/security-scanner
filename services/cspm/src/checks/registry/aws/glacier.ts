// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const glacierChecks: CheckMetadata[] = [
  {
    checkId: 'glacier_vaults_policy_public_access',
    provider: 'aws',
    service: 'glacier',
    title: 'Glacier Vault Policy Allows Public Access',
    severity: 'CRITICAL',
    description: 'Checks that S3 Glacier vault access policies contain no Allow statements granting access to everyone (Principal "*", AWS "*" or CanonicalUser "*"), which would let anyone list, retrieve or delete archives.',
    remediation: 'Remove or rewrite the public policy statements: restrict principals to specific AWS accounts or roles, grant only required actions, and consider Vault Lock for immutable retention. To fully remove a public policy: aws glacier delete-vault-access-policy --account-id <account> --vault-name <vault>.',
    tags: ['glacier', 'public-access', 'resource-policy'],
  },
];
