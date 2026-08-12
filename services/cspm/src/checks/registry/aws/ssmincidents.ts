// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const ssmincidentsChecks: CheckMetadata[] = [
  {
    checkId: 'ssmincidents_enabled_with_plans',
    provider: 'aws',
    service: 'ssmincidents',
    title: 'Incident Manager Not Ready With Response Plans',
    severity: 'MEDIUM',
    description: 'Checks that AWS Systems Manager Incident Manager has an ACTIVE replication set and at least one response plan, so incidents can be tracked and coordinated.',
    remediation: 'Create an Incident Manager replication set covering at least one region, wait for it to become ACTIVE, and define at least one response plan with an incident template, escalation contacts and runbooks.',
    tags: ['ssmincidents', 'incident-response', 'resilience', 'monitoring'],
  },
];
