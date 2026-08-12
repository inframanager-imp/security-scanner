// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const wellarchitectedChecks: CheckMetadata[] = [
  {
    checkId: 'wellarchitected_workload_no_high_or_medium_risks',
    provider: 'aws',
    service: 'wellarchitected',
    title: 'Well-Architected Workload Has High or Medium Risks',
    severity: 'MEDIUM',
    description: 'Checks that workloads reviewed in the AWS Well-Architected Tool carry no unresolved HIGH or MEDIUM risk items across the framework pillars.',
    remediation: 'Open the workload in the Well-Architected Tool, work through the improvement plan prioritizing HIGH then MEDIUM risks, and update answers to the recommended best-practice choices until both counts reach zero.',
    tags: ['wellarchitected', 'governance', 'resilience'],
  },
];
