// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const servicecatalogChecks: CheckMetadata[] = [
  {
    checkId: 'servicecatalog_portfolio_shared_within_organization_only',
    provider: 'aws',
    service: 'servicecatalog',
    title: 'Service Catalog Portfolio Shared Outside Organization',
    severity: 'HIGH',
    description: 'Checks that Service Catalog portfolios in organization member accounts are shared only through AWS Organizations, not directly with individual accounts, which bypasses centralized guardrails.',
    remediation: 'Remove portfolio shares of type ACCOUNT and re-share the portfolio through AWS Organizations (organization, OU, or organization member scope) so launch constraints and governance stay centralized.',
    tags: ['servicecatalog', 'sharing', 'trust-boundaries', 'governance'],
  },
];
