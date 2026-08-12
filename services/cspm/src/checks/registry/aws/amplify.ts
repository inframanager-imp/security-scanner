// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const amplifyChecks: CheckMetadata[] = [
  {
    checkId: 'amplify_app_no_secrets_in_environment',
    provider: 'aws',
    service: 'amplify',
    title: 'Amplify App Secrets in Environment or Build Settings',
    severity: 'HIGH',
    description: 'Checks Amplify apps and their branches for hardcoded credentials (API keys, tokens, passwords) in environment variables or build settings (buildSpec), where they are readable by anyone with console access and can leak during builds.',
    remediation: 'Remove plaintext secrets from Amplify environment variables and buildSpec; store them in AWS Secrets Manager or SSM Parameter Store and reference them securely at build time.',
    tags: ['amplify', 'secrets', 'credentials'],
  },
];
