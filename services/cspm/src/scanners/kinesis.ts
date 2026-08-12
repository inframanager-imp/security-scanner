// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  KinesisClient,
  ListStreamsCommand,
  DescribeStreamSummaryCommand,
} from '@aws-sdk/client-kinesis';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Prowler default for min_kinesis_stream_retention_hours
const MIN_RETENTION_HOURS = 168;

export class KinesisScanner extends BaseScanner {
  private kinesis: KinesisClient;

  constructor(client: AWSClient) {
    super(client, 'Kinesis');
    this.kinesis = new KinesisClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Kinesis security scan...');

      const streamNames = await this.listStreams();
      for (const streamName of streamNames) {
        logger.debug(`Scanning Kinesis stream: ${streamName}`);
        const streamFindings = await this.validateStream(streamName);
        findings.push(...streamFindings);
      }

      logger.info(`Kinesis scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Kinesis scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listStreams(): Promise<string[]> {
    return retry(async () => {
      logger.debug('Fetching Kinesis streams...');
      const names: string[] = [];
      let nextToken: string | undefined;
      do {
        const result: any = await this.kinesis.send(
          new ListStreamsCommand(nextToken ? { NextToken: nextToken } : {})
        );
        names.push(...(result.StreamNames || []));
        nextToken = result.NextToken;
      } while (nextToken);
      return names;
    });
  }

  private async validateStream(streamName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    let summary: any;
    try {
      const result: any = await retry(async () => {
        return await this.kinesis.send(
          new DescribeStreamSummaryCommand({ StreamName: streamName })
        );
      });
      summary = result.StreamDescriptionSummary || {};
    } catch (error) {
      logger.debug(`Failed to describe Kinesis stream ${streamName}`, { error: (error as Error).message });
      return findings;
    }

    const evidence = { stream: streamName, streamArn: summary.StreamARN };

    // kinesis_stream_encrypted_at_rest (Prowler): EncryptionType must be KMS
    const encryptionType = summary.EncryptionType || 'NONE';
    if (encryptionType !== 'KMS') {
      findings.push(this.emit(
        'kinesis_stream_encrypted_at_rest',
        { ...evidence, encryptionType },
        { message: `Kinesis stream "${streamName}" is not encrypted at rest with KMS server-side encryption` }
      ));
    } else {
      // kinesis_stream_encrypted_with_cmk (supplemental best practice):
      // the AWS-managed key alias/aws/kinesis offers no key policy control or rotation ownership
      const keyId = summary.KeyId || '';
      if (keyId.includes('alias/aws/kinesis')) {
        findings.push(this.emit(
          'kinesis_stream_encrypted_with_cmk',
          { ...evidence, keyId },
          { message: `Kinesis stream "${streamName}" is encrypted with the AWS-managed key (alias/aws/kinesis) instead of a customer-managed KMS key` }
        ));
      }
    }

    // kinesis_stream_data_retention_period (Prowler): retention >= 168 hours
    const retentionPeriodHours = summary.RetentionPeriodHours ?? 24;
    if (retentionPeriodHours < MIN_RETENTION_HOURS) {
      findings.push(this.emit(
        'kinesis_stream_data_retention_period',
        { ...evidence, retentionPeriodHours, minimumHours: MIN_RETENTION_HOURS },
        { message: `Kinesis stream "${streamName}" retains data for only ${retentionPeriodHours} hours, below the recommended minimum of ${MIN_RETENTION_HOURS} hours` }
      ));
    }

    // kinesis_stream_enhanced_monitoring_enabled (supplemental best practice):
    // shard-level metrics are needed to detect abnormal consumption patterns per shard
    const shardLevelMetrics = summary.EnhancedMonitoring?.[0]?.ShardLevelMetrics || [];
    if (shardLevelMetrics.length === 0) {
      findings.push(this.emit(
        'kinesis_stream_enhanced_monitoring_enabled',
        { ...evidence, shardLevelMetrics },
        { message: `Kinesis stream "${streamName}" does not have enhanced (shard-level) monitoring enabled` }
      ));
    }

    return findings;
  }
}

export default KinesisScanner;
