import {
  ListQueuesCommand,
  GetQueueAttributesCommand,
} from '@aws-sdk/client-sqs';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class SQSScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'SQS');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting SQS security scan...');

    const urls = await this.listQueues();
    logger.info(`SQS: scanning ${urls.length} queue(s)`);

    for (const url of urls) {
      findings.push(...(await this.scanQueue(url)));
    }

    logger.info(`SQS scan complete. ${findings.length} findings.`);
    return findings;
  }

  private async listQueues(): Promise<string[]> {
    const urls: string[] = [];
    let nextToken: string | undefined;
    try {
      do {
        const result = await retry(() =>
          this.client.sqs.send(new ListQueuesCommand({ NextToken: nextToken, MaxResults: 1000 }))
        );
        urls.push(...(result.QueueUrls ?? []));
        nextToken = result.NextToken;
      } while (nextToken);
    } catch { /* no permission */ }
    return urls;
  }

  private async scanQueue(queueUrl: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const queueName = queueUrl.split('/').pop() ?? queueUrl;

    let attrs: Record<string, string> = {};
    try {
      const result = await retry(() =>
        this.client.sqs.send(new GetQueueAttributesCommand({
          QueueUrl: queueUrl,
          AttributeNames: ['All'],
        }))
      );
      attrs = result.Attributes ?? {};
    } catch { return findings; }

    const queueArn = attrs.QueueArn ?? queueUrl;

    // 1. Public access via policy
    if (attrs.Policy) {
      try {
        const policy = JSON.parse(attrs.Policy);
        const hasPublic = (policy.Statement ?? []).some((stmt: any) => {
          const principal = stmt.Principal;
          return (
            stmt.Effect === 'Allow' &&
            (principal === '*' || principal?.AWS === '*')
          );
        });
        if (hasPublic) {
          findings.push(this.createFinding(
            'SQS Queue Allows Public Access',
            `SQS queue "${queueName}" has a policy granting access to all principals ("*"). ` +
            `Any AWS account can send to or receive from this queue.`,
            'CRITICAL',
            { resourceId: queueArn, queueName, queueArn, queueUrl },
            `Update the SQS queue policy to restrict the Principal to specific AWS accounts or IAM roles. ` +
            `Remove any Statement with Principal: "*".`,
            ['sqs', 'access-control'],
          ));
        }
      } catch { /* invalid policy JSON */ }
    }

    // 2. No SSE encryption
    const kmsKeyId     = attrs.KmsMasterKeyId ?? '';
    const sqsEncrypted = attrs.SqsManagedSseEnabled === 'true';
    if (!kmsKeyId && !sqsEncrypted) {
      findings.push(this.createFinding(
        'SQS Queue Not Encrypted',
        `SQS queue "${queueName}" does not have server-side encryption enabled. ` +
        `Messages are stored unencrypted and may expose sensitive data.`,
        'MEDIUM',
        { resourceId: `${queueArn}::encryption`, queueName, queueArn },
        `Enable SSE: aws sqs set-queue-attributes --queue-url ${queueUrl} ` +
        `--attributes KmsMasterKeyId=alias/aws/sqs`,
        ['sqs', 'encryption'],
      ));
    }

    // 3. No dead-letter queue configured
    const redrivePolicy = attrs.RedrivePolicy ?? '';
    if (!redrivePolicy) {
      findings.push(this.createFinding(
        'SQS Queue Has No Dead-Letter Queue',
        `SQS queue "${queueName}" has no dead-letter queue (DLQ) configured. ` +
        `Failed messages will be retried indefinitely and eventually lost, making failures invisible.`,
        'LOW',
        { resourceId: `${queueArn}::dlq`, queueName, queueArn },
        `Configure a DLQ: create a separate SQS queue and set it as the RedrivePolicy target ` +
        `with a maxReceiveCount of 3-5.`,
        ['sqs', 'reliability'],
      ));
    }

    return findings;
  }
}

export default SQSScanner;
