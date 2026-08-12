// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const apigatewayv2Checks: CheckMetadata[] = [
  {
    checkId: 'apigatewayv2_api_access_logging_enabled',
    provider: 'aws',
    service: 'apigatewayv2',
    title: 'API Gateway V2 Stage Access Logging Disabled',
    severity: 'MEDIUM',
    description: 'Checks that each API Gateway V2 (HTTP/WebSocket) API stage has access logging configured to a destination such as CloudWatch Logs; without it API calls lack traceability for detecting misuse or anomalous traffic.',
    remediation: 'Enable access logging on the stage with a CloudWatch Logs destination ARN and a structured log format, set retention, and integrate logs with monitoring and alerting.',
    tags: ['apigatewayv2', 'logging', 'audit'],
  },
  {
    checkId: 'apigatewayv2_api_authorizers_enabled',
    provider: 'aws',
    service: 'apigatewayv2',
    title: 'API Gateway V2 API Without Authorizer',
    severity: 'MEDIUM',
    description: 'Checks that each API Gateway V2 API has an authorizer (JWT/Cognito or Lambda) configured; without one, any caller can invoke the API routes.',
    remediation: 'Create a JWT/Cognito or Lambda authorizer for the API and attach it to routes so only authenticated principals can invoke them; add throttling and WAF for defense in depth.',
    tags: ['apigatewayv2', 'authorization', 'identity-access'],
  },
];
