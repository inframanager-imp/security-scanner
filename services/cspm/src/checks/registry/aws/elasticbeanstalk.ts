// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const elasticbeanstalkChecks: CheckMetadata[] = [
  {
    checkId: 'elasticbeanstalk_environment_cloudwatch_logging_enabled',
    provider: 'aws',
    service: 'elasticbeanstalk',
    title: 'Elastic Beanstalk Logs Not Streamed to CloudWatch',
    severity: 'HIGH',
    description: 'Checks that Elastic Beanstalk environments stream instance and proxy logs to CloudWatch Logs (StreamLogs enabled); without centralized logging, logs can be lost on rotation or instance termination and attackers can erase local evidence.',
    remediation: 'Enable log streaming (aws:elasticbeanstalk:cloudwatch:logs StreamLogs=true) on the environment, set retention, and centralize log analysis and alerting.',
    tags: ['elasticbeanstalk', 'logging', 'audit'],
  },
  {
    checkId: 'elasticbeanstalk_environment_enhanced_health_reporting',
    provider: 'aws',
    service: 'elasticbeanstalk',
    title: 'Elastic Beanstalk Enhanced Health Reporting Disabled',
    severity: 'LOW',
    description: 'Checks that Elastic Beanstalk environments use enhanced health reporting instead of basic; enhanced health surfaces instance and deployment issues early, reducing detection time and outage risk.',
    remediation: 'Set health reporting SystemType to enhanced (aws:elasticbeanstalk:healthreporting:system) on the environment and monitor the additional health metrics.',
    tags: ['elasticbeanstalk', 'monitoring', 'resilience'],
  },
  {
    checkId: 'elasticbeanstalk_environment_managed_updates_enabled',
    provider: 'aws',
    service: 'elasticbeanstalk',
    title: 'Elastic Beanstalk Managed Platform Updates Disabled',
    severity: 'HIGH',
    description: 'Checks that Elastic Beanstalk environments have managed platform updates enabled so platform patch and minor updates are applied automatically during a maintenance window; patch drift leaves OS/runtime CVEs exploitable.',
    remediation: 'Enable managed actions (aws:elasticbeanstalk:managedactions ManagedActionsEnabled=true) with a scheduled maintenance window and an appropriate update level for the environment.',
    tags: ['elasticbeanstalk', 'patching', 'updates'],
  },
];
