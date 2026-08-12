// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const datasyncChecks: CheckMetadata[] = [
  {
    checkId: 'datasync_task_logging_enabled',
    provider: 'aws',
    service: 'datasync',
    title: 'DataSync Task Logging Disabled',
    severity: 'HIGH',
    description: 'Checks that each DataSync task has a CloudWatch Logs log group configured (CloudWatchLogGroupArn), so transfer executions publish logs for monitoring and forensics.',
    remediation: 'Configure a CloudWatch Logs log group on the task (aws datasync update-task --cloud-watch-log-group-arn), choose an appropriate log level, set log retention, and centralize log analysis and alerting.',
    tags: ['datasync', 'logging', 'audit'],
  },
];
