// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const appsyncChecks: CheckMetadata[] = [
  {
    checkId: 'appsync_field_level_logging_enabled',
    provider: 'aws',
    service: 'appsync',
    title: 'AppSync API Field-Level Logging Disabled',
    severity: 'MEDIUM',
    description: 'Checks that AppSync GraphQL APIs have field-level (resolver) logging set to ALL or ERROR; without it resolver access and mutations lack auditability, hindering detection and incident response.',
    remediation: 'Enable logging on the API with field resolver log level ERROR (or ALL), assign a least-privilege IAM role for CloudWatch Logs delivery, and set log retention.',
    tags: ['appsync', 'logging', 'audit'],
  },
  {
    checkId: 'appsync_graphql_api_no_api_key_authentication',
    provider: 'aws',
    service: 'appsync',
    title: 'AppSync GraphQL API Using API Key Authentication',
    severity: 'HIGH',
    description: 'Checks that AppSync GraphQL APIs do not use API_KEY as the default authorization mode; static API keys can be leaked or reused, enabling unauthorized queries and mutations with no user identity for auditing.',
    remediation: 'Switch the default authorization mode to AWS_IAM, Cognito User Pools, OIDC, or a Lambda authorizer. If guest access is unavoidable, limit it to read-only fields with throttling and short key lifetimes.',
    tags: ['appsync', 'authentication', 'identity-access'],
  },
];
