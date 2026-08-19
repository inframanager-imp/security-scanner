import {
  ListTopicsCommand,
  GetTopicAttributesCommand,
  type Topic,
} from '@aws-sdk/client-sns';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class SNSScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'SNS');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting SNS security scan...');

    const topics = await this.listTopics();
    logger.info(`SNS: scanning ${topics.length} topic(s)`);

    for (const topic of topics) {
      findings.push(...(await this.scanTopic(topic)));
    }

    logger.info(`SNS scan complete. ${findings.length} findings.`);
    return findings;
  }

  private async listTopics(): Promise<Topic[]> {
    const topics: Topic[] = [];
    let nextToken: string | undefined;
    try {
      do {
        const result = await retry(() =>
          this.client.sns.send(new ListTopicsCommand({ NextToken: nextToken }))
        );
        topics.push(...(result.Topics ?? []));
        nextToken = result.NextToken;
      } while (nextToken);
    } catch { /* no permission */ }
    return topics;
  }

  private async scanTopic(topic: Topic): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const arn       = topic.TopicArn ?? '';
    const topicName = arn.split(':').pop() ?? arn;

    let attrs: Record<string, string> = {};
    try {
      const result = await retry(() =>
        this.client.sns.send(new GetTopicAttributesCommand({ TopicArn: arn }))
      );
      attrs = result.Attributes ?? {};
    } catch { return findings; }

    // 1. Public access (policy allows Principal: *)
    const policy = attrs.Policy ? JSON.parse(attrs.Policy) : null;
    if (policy) {
      const hasPublic = (policy.Statement ?? []).some((stmt: any) => {
        const principal = stmt.Principal;
        return (
          stmt.Effect === 'Allow' &&
          (principal === '*' || principal?.AWS === '*' || principal?.Service === '*')
        );
      });
      if (hasPublic) {
        findings.push(this.emit(
          'sns_topics_not_publicly_accessible',
          { resourceId: arn, topicName, topicArn: arn },
          {
            message: `SNS topic "${topicName}" has a resource policy that grants access to all principals ("*"). ` +
              `Any AWS account or unauthenticated user may be able to publish or subscribe to this topic.`,
          }
        ));
      }
    }

    // 2. No SSE (server-side encryption)
    const kmsMasterKeyId = attrs.KmsMasterKeyId ?? '';
    if (!kmsMasterKeyId) {
      findings.push(this.emit(
        'sns_topics_kms_encryption_at_rest_enabled',
        { resourceId: `${arn}::encryption`, topicName, topicArn: arn },
        {
          message: `SNS topic "${topicName}" does not have server-side encryption (SSE) enabled. ` +
            `Messages stored in the topic are not encrypted at rest.`,
          remediation: `Enable SSE: aws sns set-topic-attributes --topic-arn ${arn} ` +
            `--attribute-name KmsMasterKeyId --attribute-value alias/aws/sns`,
        }
      ));
    }

    return findings;
  }
}

export default SNSScanner;
