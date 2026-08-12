// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  FirehoseClient,
  ListDeliveryStreamsCommand,
  DescribeDeliveryStreamCommand,
} from '@aws-sdk/client-firehose';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class FirehoseScanner extends BaseScanner {
  private firehose: FirehoseClient;

  constructor(client: AWSClient) {
    super(client, 'Firehose');
    this.firehose = new FirehoseClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Firehose security scan...');

      const streamNames = await this.listDeliveryStreams();
      logger.info(`Firehose: scanning ${streamNames.length} delivery stream(s)`);

      for (const streamName of streamNames) {
        try {
          findings.push(...(await this.validateStream(streamName)));
        } catch (error) {
          logger.debug(`Failed to scan Firehose stream ${streamName}`, { error: (error as Error).message });
        }
      }

      logger.info(`Firehose scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Firehose scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listDeliveryStreams(): Promise<string[]> {
    const streamNames: string[] = [];
    const seen = new Set<string>();
    let exclusiveStartName: string | undefined;

    // Firehose paginates via ExclusiveStartDeliveryStreamName + HasMoreDeliveryStreams
    for (;;) {
      const result = await retry(async () => {
        return await this.firehose.send(new ListDeliveryStreamsCommand(
          exclusiveStartName ? { ExclusiveStartDeliveryStreamName: exclusiveStartName } : {}
        ));
      });
      const names = result.DeliveryStreamNames ?? [];
      for (const name of names) {
        if (!seen.has(name)) {
          seen.add(name);
          streamNames.push(name);
        }
      }
      if (!result.HasMoreDeliveryStreams || names.length === 0) break;
      exclusiveStartName = names[names.length - 1];
    }

    return streamNames;
  }

  private async validateStream(streamName: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const result = await retry(async () => {
      return await this.firehose.send(new DescribeDeliveryStreamCommand({ DeliveryStreamName: streamName }));
    });
    const description: any = result.DeliveryStreamDescription;
    if (!description) return findings;

    const streamArn: string = description.DeliveryStreamARN ?? streamName;
    const encryptionStatus: string = description.DeliveryStreamEncryptionConfiguration?.Status ?? 'DISABLED';
    const streamType: string = description.DeliveryStreamType ?? '';

    // firehose_stream_encrypted_at_rest: SSE must be ENABLED. MSK-sourced
    // streams are exempt because MSK always encrypts data at rest.
    if (encryptionStatus !== 'ENABLED' && streamType !== 'MSKAsSource') {
      let message = `Firehose stream "${streamName}" does not have at rest encryption enabled`;
      if (streamType === 'KinesisStreamAsSource') {
        const sourceStreamArn: string =
          description.Source?.KinesisStreamSourceDescription?.KinesisStreamARN ?? '';
        message += sourceStreamArn
          ? `; it reads from Kinesis stream ${sourceStreamArn}, whose encryption does not extend to data buffered by Firehose`
          : '';
      }
      findings.push(this.emit(
        'firehose_stream_encrypted_at_rest',
        {
          resourceId: streamArn,
          streamName,
          streamArn,
          deliveryStreamType: streamType,
          encryptionStatus,
        },
        {
          message,
          remediation: `Enable server-side encryption on stream "${streamName}": aws firehose start-delivery-stream-encryption --delivery-stream-name ${streamName}`,
        }
      ));
    }

    return findings;
  }
}

export default FirehoseScanner;
