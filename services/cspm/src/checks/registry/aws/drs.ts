// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const drsChecks: CheckMetadata[] = [
  {
    checkId: 'drs_job_exist',
    provider: 'aws',
    service: 'drs',
    title: 'Elastic Disaster Recovery Inactive or Untested',
    severity: 'MEDIUM',
    description: 'Checks that AWS Elastic Disaster Recovery (DRS) is initialized in the region and has at least one recovery or drill job, demonstrating that failover has been exercised.',
    remediation: 'Initialize DRS in required regions, add source servers and wait for healthy replication, then run regular recovery drills to validate launch settings; define RTO/RPO, monitor replication health, and document failover procedures.',
    tags: ['drs', 'disaster-recovery', 'resilience'],
  },
];
