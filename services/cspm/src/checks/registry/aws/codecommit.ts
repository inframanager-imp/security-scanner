// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const codecommitChecks: CheckMetadata[] = [
  {
    checkId: 'codecommit_repository_no_secrets',
    provider: 'aws',
    service: 'codecommit',
    title: 'CodeCommit Repository Default Branch Contains Secrets',
    severity: 'HIGH',
    description: 'Checks the files at the tip of each CodeCommit repository default branch for hardcoded credentials such as AWS keys, passwords, tokens and private keys; committed secrets are readable by anyone with repository access and persist in commit history.',
    remediation: 'Remove hardcoded credentials from the repository and rotate them immediately (they remain recoverable from commit history); store secrets in AWS Secrets Manager or SSM Parameter Store and add pre-commit secret scanning to prevent recurrence.',
    tags: ['codecommit', 'secrets', 'credentials', 'ci-cd'],
  },
];
