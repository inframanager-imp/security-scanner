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
        findings.push(this.createFinding(
          'No CloudTrail Found',
          'CloudTrail is not configured in this region',
          'MEDIUM',
          { region: this.client.getRegion() },
          'Enable CloudTrail to log all API activity for auditing and compliance',
          ['cloudtrail', 'logging', 'audit']
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
        findings.push(this.createFinding(
          'CloudTrail Not Logging',
          `Trail "${trailName}" is not actively logging events`,
          'HIGH',
          { trailName, isLogging: statusResult.IsLogging },
          `Enable logging for trail "${trailName}" to ensure all API calls are recorded`,
          ['cloudtrail', 'logging', 'active-monitoring']
        ));
      }

      // Check multi-region
      if (!trail.IsMultiRegionTrail) {
        findings.push(this.createFinding(
          'Single Region CloudTrail',
          `Trail "${trailName}" is not multi-region. API activity in other regions may not be logged.`,
          'HIGH',
          { trailName, isMultiRegion: trail.IsMultiRegionTrail },
          `Enable multi-region logging for trail "${trailName}"`,
          ['cloudtrail', 'multi-region']
        ));
      }

      // Check S3 logging
      if (!trail.S3BucketName) {
        findings.push(this.createFinding(
          'S3 Bucket Not Configured',
          `Trail "${trailName}" is not logging to an S3 bucket`,
          'CRITICAL',
          { trailName, s3Bucket: trail.S3BucketName },
          `Configure S3 bucket logging for trail "${trailName}"`,
          ['cloudtrail', 's3', 'logging']
        ));
      }

      // Check log file validation
      if (!trail.LogFileValidationEnabled) {
        findings.push(this.createFinding(
          'Log File Validation Not Enabled',
          `Trail "${trailName}" does not have log file validation enabled`,
          'MEDIUM',
          { trailName, logFileValidation: trail.LogFileValidationEnabled },
          `Enable log file validation for trail "${trailName}" to detect unauthorized modifications`,
          ['cloudtrail', 'integrity', 'logging']
        ));
      }

      // Check CloudWatch Logs
      if (!trail.CloudWatchLogsLogGroupArn) {
        findings.push(this.createFinding(
          'CloudWatch Logs Not Configured',
          `Trail "${trailName}" is not logging to CloudWatch Logs for real-time monitoring`,
          'MEDIUM',
          { trailName, cwLogs: trail.CloudWatchLogsLogGroupArn },
          `Configure CloudWatch Logs destination for trail "${trailName}" for real-time alerts`,
          ['cloudtrail', 'cloudwatch', 'monitoring']
        ));
      }

      // Check KMS encryption
      if (!trail.KMSKeyId) {
        findings.push(this.createFinding(
          'S3 Logs Not KMS Encrypted',
          `Trail "${trailName}" S3 logs may not be using KMS encryption`,
          'MEDIUM',
          { trailName, kmsKey: trail.KMSKeyId },
          `Enable KMS encryption for S3 logs of trail "${trailName}"`,
          ['cloudtrail', 'kms', 'encryption']
        ));
      }

      // Check management events
      if (trail.EventSelectors) {
        const hasManagementEvents = trail.EventSelectors.some((es: any) => es.IncludeManagementEvents);
        if (!hasManagementEvents) {
          findings.push(this.createFinding(
            'Management Events Not Logged',
            `Trail "${trailName}" is not logging management events`,
            'HIGH',
            { trailName, eventSelectors: trail.EventSelectors },
            `Enable management event logging for trail "${trailName}"`,
            ['cloudtrail', 'management-events']
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
