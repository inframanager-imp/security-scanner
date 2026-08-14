// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const appinsightsChecks: CheckMetadata[] = [
  {
    checkId: 'appinsights_ensure_is_configured',
    provider: 'azure',
    service: 'appinsights',
    title: 'Subscription Has Application Insights Configured',
    severity: 'LOW',
    description: 'Checks that the subscription has at least one Application Insights resource collecting application telemetry (metrics, traces, logs), indicating that application-level monitoring and observability is in place.',
    remediation: 'Create an Application Insights component (Azure Monitor > Application Insights > Create) for critical workloads and centralize telemetry in a Log Analytics workspace with actionable alerts.',
    tags: ['appinsights', 'logging', 'monitoring'],
  },
];
