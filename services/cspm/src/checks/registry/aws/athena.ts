// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const athenaChecks: CheckMetadata[] = [
  {
    checkId: 'athena_workgroup_encryption',
    provider: 'aws',
    service: 'athena',
    title: 'Athena Workgroup Query Results Not Encrypted',
    severity: 'MEDIUM',
    description: 'Checks that enabled Athena workgroups with recent query activity encrypt query results at rest using SSE_S3, SSE_KMS or CSE_KMS.',
    remediation: 'Configure result encryption on the workgroup result configuration, preferring SSE-KMS or CSE-KMS with a customer-managed key, and enforce the workgroup configuration so clients cannot override it.',
    tags: ['athena', 'encryption'],
  },
  {
    checkId: 'athena_workgroup_enforce_configuration',
    provider: 'aws',
    service: 'athena',
    title: 'Athena Workgroup Configuration Not Enforced',
    severity: 'MEDIUM',
    description: 'Checks that Athena workgroups enforce the workgroup configuration so client-side settings cannot override the result location and encryption options.',
    remediation: 'Set EnforceWorkGroupConfiguration=true on the workgroup so the output location and encryption defined by the workgroup always apply, regardless of client-side settings.',
    tags: ['athena', 'configuration', 'encryption'],
  },
  {
    checkId: 'athena_workgroup_logging_enabled',
    provider: 'aws',
    service: 'athena',
    title: 'Athena Workgroup CloudWatch Logging Disabled',
    severity: 'MEDIUM',
    description: 'Checks that Athena workgroups publish query metrics to CloudWatch so query activity can be monitored and audited.',
    remediation: 'Enable PublishCloudWatchMetricsEnabled on the workgroup and build alarms and dashboards over the emitted query metrics to detect anomalous usage.',
    tags: ['athena', 'logging', 'monitoring'],
  },
];
