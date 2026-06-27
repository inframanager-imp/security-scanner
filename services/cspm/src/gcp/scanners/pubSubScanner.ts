import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class GcpPubSubScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-PubSub');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      const pubsub = this.client.pubsub();

      // List all topics
      const topicRes = await pubsub.projects.topics.list({
        project: `projects/${project}`,
        pageSize: 500,
      });
      const topics = topicRes.data.topics ?? [];

      for (const topic of topics) {
        const topicName = topic.name?.split('/').pop() ?? 'unknown';

        // 1. No CMEK on topic
        if (!topic.kmsKeyName) {
          findings.push(this.finding(
            'Pub/Sub topic does not use a customer-managed encryption key',
            `Pub/Sub topic "${topicName}" in project "${project}" uses Google-managed encryption. CMEK provides control over key lifecycle and enables data access revocation by disabling the KMS key.`,
            'MEDIUM',
            { topic: topicName, project },
            'Configure a Cloud KMS key as the CMEK for this topic using the kmsKeyName field. Grant the Pub/Sub service account Cloud KMS CryptoKey Encrypter/Decrypter permissions.',
            ['pubsub', 'encryption', 'cmek'],
          ));
        }

        // 2. Public IAM access on topic
        try {
          const iamRes = await pubsub.projects.topics.getIamPolicy({
            resource: topic.name!,
          });
          const bindings = iamRes.data.bindings ?? [];
          const publicBinding = bindings.find(b =>
            (b.members ?? []).some(m => m === 'allUsers' || m === 'allAuthenticatedUsers'),
          );
          if (publicBinding) {
            findings.push(this.finding(
              'Pub/Sub topic is publicly accessible',
              `Pub/Sub topic "${topicName}" in project "${project}" has a public IAM binding with role "${publicBinding.role}". Any internet user can publish or subscribe to this topic.`,
              'CRITICAL',
              { topic: topicName, project, publicRole: publicBinding.role },
              'Remove allUsers and allAuthenticatedUsers from the topic IAM policy immediately.',
              ['pubsub', 'public-access'],
            ));
          }
        } catch { /* IAM check optional */ }

        // 3. No retention policy (messages may be lost before processing)
        if (!topic.messageRetentionDuration) {
          findings.push(this.finding(
            'Pub/Sub topic has no message retention policy configured',
            `Pub/Sub topic "${topicName}" in project "${project}" has no message retention. Without retention, messages are not stored after delivery; if all subscriptions fall behind or are deleted, messages are unrecoverable.`,
            'LOW',
            { topic: topicName, project },
            'Configure messageRetentionDuration on the topic (up to 7 days) to retain messages for replay and recovery.',
            ['pubsub', 'data-retention'],
          ));
        }
      }

      // List all subscriptions
      const subRes = await pubsub.projects.subscriptions.list({
        project: `projects/${project}`,
        pageSize: 500,
      });
      const subscriptions = subRes.data.subscriptions ?? [];

      for (const sub of subscriptions) {
        const subName = sub.name?.split('/').pop() ?? 'unknown';

        // 4. Push subscription with HTTP (not HTTPS) endpoint
        if (sub.pushConfig?.pushEndpoint?.startsWith('http://')) {
          findings.push(this.finding(
            'Pub/Sub push subscription uses an unencrypted HTTP endpoint',
            `Pub/Sub subscription "${subName}" in project "${project}" pushes messages to an HTTP endpoint "${sub.pushConfig.pushEndpoint}". Messages are transmitted in plaintext and can be intercepted.`,
            'HIGH',
            { subscription: subName, project, endpoint: sub.pushConfig.pushEndpoint },
            'Update the push endpoint to use HTTPS. Ensure the endpoint has a valid TLS certificate.',
            ['pubsub', 'tls', 'push-subscription'],
          ));
        }

        // 5. Subscription with no message retention (default 7 days is fine, but 0 is risky)
        const ackDeadlineSecs = sub.ackDeadlineSeconds ?? 10;
        if (ackDeadlineSecs < 10) {
          findings.push(this.finding(
            'Pub/Sub subscription has a very short acknowledgment deadline',
            `Pub/Sub subscription "${subName}" has an ack deadline of ${ackDeadlineSecs} seconds. Very short deadlines cause messages to be redelivered frequently, leading to duplicate processing and potential message loss under load.`,
            'LOW',
            { subscription: subName, project, ackDeadlineSeconds: ackDeadlineSecs },
            'Set the ackDeadlineSeconds to at least 10 seconds, and higher for subscriptions processing slow tasks (up to 600 seconds).',
            ['pubsub', 'reliability'],
          ));
        }

        // 6. Dead letter topic not configured (no poison pill handling)
        if (!sub.deadLetterPolicy?.deadLetterTopic) {
          findings.push(this.finding(
            'Pub/Sub subscription has no dead letter topic configured',
            `Pub/Sub subscription "${subName}" in project "${project}" has no dead letter policy. Messages that fail processing are retried indefinitely or discarded, making failed message debugging difficult.`,
            'LOW',
            { subscription: subName, project },
            'Configure a dead letter topic (deadLetterPolicy) with a maxDeliveryAttempts threshold (e.g., 5) to capture unprocessable messages for investigation.',
            ['pubsub', 'reliability'],
          ));
        }

        // 7. Public IAM access on subscription
        try {
          const iamRes = await pubsub.projects.subscriptions.getIamPolicy({
            resource: sub.name!,
          });
          const bindings = iamRes.data.bindings ?? [];
          const publicBinding = bindings.find(b =>
            (b.members ?? []).some(m => m === 'allUsers' || m === 'allAuthenticatedUsers'),
          );
          if (publicBinding) {
            findings.push(this.finding(
              'Pub/Sub subscription is publicly accessible',
              `Pub/Sub subscription "${subName}" in project "${project}" has a public IAM binding with role "${publicBinding.role}". Any internet user can pull messages from this subscription.`,
              'CRITICAL',
              { subscription: subName, project, publicRole: publicBinding.role },
              'Remove allUsers and allAuthenticatedUsers from the subscription IAM policy immediately.',
              ['pubsub', 'public-access'],
            ));
          }
        } catch { /* IAM check optional */ }
      }
    } catch (err) {
      findings.push(this.finding(
        'GCP Pub/Sub scan error',
        `Could not complete Pub/Sub scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service account has roles/pubsub.viewer on the project.',
      ));
    }

    return findings;
  }
}
