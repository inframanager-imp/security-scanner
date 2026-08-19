import {
  DescribeTrailsCommand,
  GetTrailStatusCommand
} from '@aws-sdk/client-cloudtrail';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class CloudTrailScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'CloudTrail');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting CloudTrail security scan...');

      // Discover all trails
      const trails = await this.discoverTrails();
      if (trails.length === 0) {
        findings.push(this.emit(
          'cloudtrail_trail_not_configured',
          { region: this.client.getRegion() },
          {
            message: 'CloudTrail is not configured in this region',
          }
        ));
        return findings;
      }

      // Check each trail configuration
      for (const trail of trails) {
        const trailFindings = await this.validateTrailConfiguration(trail);
        findings.push(...trailFindings);
      }

      logger.info(`CloudTrail scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('CloudTrail scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async discoverTrails(): Promise<any[]> {
    return retry(async () => {
      logger.debug('Discovering CloudTrail trails...');
      
      const describeCmd = new DescribeTrailsCommand({
        includeShadowTrails: true
      });
      const result = await this.client.cloudtrail.send(describeCmd);
      
      return result.trailList || [];
    });
  }

  private async validateTrailConfiguration(trail: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const trailName = trail.Name || trail.TrailARN?.split('/')?.pop() || 'Unknown';

    try {
      // Check if trail is logging
      const statusResult = await retry(async () => {
        const cmd = new GetTrailStatusCommand({ Name: trailName });
        return await this.client.cloudtrail.send(cmd);
      });

      if (!statusResult.IsLogging) {
        findings.push(this.emit(
          'cloudtrail_trail_not_logging',
          { trailName, isLogging: statusResult.IsLogging },
          {
            message: `Trail "${trailName}" is not actively logging events`,
            remediation: `Enable logging for trail "${trailName}" to ensure all API calls are recorded`,
          }
        ));
      }

      // Check multi-region
      if (!trail.IsMultiRegionTrail) {
        findings.push(this.emit(
          'cloudtrail_multi_region_enabled',
          { trailName, isMultiRegion: trail.IsMultiRegionTrail },
          {
            message: `Trail "${trailName}" is not multi-region. API activity in other regions may not be logged.`,
            remediation: `Enable multi-region logging for trail "${trailName}"`,
          }
        ));
      }

      // Check S3 logging
      if (!trail.S3BucketName) {
        findings.push(this.emit(
          'cloudtrail_trail_s3_bucket_not_configured',
          { trailName, s3Bucket: trail.S3BucketName },
          {
            message: `Trail "${trailName}" is not logging to an S3 bucket`,
            remediation: `Configure S3 bucket logging for trail "${trailName}"`,
          }
        ));
      }

      // Check log file validation
      if (!trail.LogFileValidationEnabled) {
        findings.push(this.emit(
          'cloudtrail_log_file_validation_enabled',
          { trailName, logFileValidation: trail.LogFileValidationEnabled },
          {
            message: `Trail "${trailName}" does not have log file validation enabled`,
            remediation: `Enable log file validation for trail "${trailName}" to detect unauthorized modifications`,
          }
        ));
      }

      // Check CloudWatch Logs
      if (!trail.CloudWatchLogsLogGroupArn) {
        findings.push(this.emit(
          'cloudtrail_cloudwatch_logging_enabled',
          { trailName, cwLogs: trail.CloudWatchLogsLogGroupArn },
          {
            message: `Trail "${trailName}" is not logging to CloudWatch Logs for real-time monitoring`,
            remediation: `Configure CloudWatch Logs destination for trail "${trailName}" for real-time alerts`,
          }
        ));
      }

      // Check KMS encryption
      if (!trail.KMSKeyId) {
        findings.push(this.emit(
          'cloudtrail_kms_encryption_enabled',
          { trailName, kmsKey: trail.KMSKeyId },
          {
            message: `Trail "${trailName}" S3 logs may not be using KMS encryption`,
            remediation: `Enable KMS encryption for S3 logs of trail "${trailName}"`,
          }
        ));
      }

      // Check management events
      if (trail.EventSelectors) {
        const hasManagementEvents = trail.EventSelectors.some((es: any) => es.IncludeManagementEvents);
        if (!hasManagementEvents) {
          findings.push(this.emit(
            'cloudtrail_multi_region_enabled_logging_management_events',
            { trailName, eventSelectors: trail.EventSelectors },
            {
              message: `Trail "${trailName}" is not logging management events`,
              remediation: `Enable management event logging for trail "${trailName}"`,
            }
          ));
        }
      }
    } catch (error) {
      logger.warn(`Failed to validate trail ${trailName}`, { error: (error as Error).message });
    }

    return findings;
  }
}

export default CloudTrailScanner;
