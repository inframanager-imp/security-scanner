import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureEventGridScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-EventGrid');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const egClient = this.client.eventGrid();

      // Scan Topics
      const topics: any[] = [];
      for await (const t of egClient.topics.listBySubscription()) topics.push(t);

      for (const topic of topics) {
        const name = topic.name ?? 'unknown';
        const rg   = topic.id?.split('/')[4] ?? 'unknown';

        // 1. Public network access
        const publicAccess = topic.publicNetworkAccess ?? 'Enabled';
        if (publicAccess === 'Enabled') {
          findings.push(this.finding(
            'Event Grid topic has public network access enabled',
            `Event Grid topic "${name}" accepts events from the public internet. Unauthorized publishers may inject malicious events into downstream event handlers.`,
            'HIGH',
            { topic: name, resourceGroup: rg },
            'Set publicNetworkAccess to "Disabled" and use Private Endpoints to allow event publishing only from trusted internal sources.',
            ['eventgrid', 'network', 'public-access'],
          ));
        }

        // 2. Local auth (SAS/access keys) — prefer managed identity
        const localAuthDisabled = topic.disableLocalAuth === true;
        if (!localAuthDisabled) {
          findings.push(this.finding(
            'Event Grid topic uses SAS key authentication instead of Microsoft Entra ID',
            `Event Grid topic "${name}" has local authentication (access keys) enabled. Publishers using access keys cannot be individually audited, rotated per-application, or revoked with fine-grained control.`,
            'MEDIUM',
            { topic: name, resourceGroup: rg },
            'Set disableLocalAuth to true and migrate all publishers to use Managed Identity or service principal authentication with Entra ID.',
            ['eventgrid', 'authentication'],
          ));
        }

        // 3. No private endpoint
        const peConns = topic.privateEndpointConnections ?? [];
        if (peConns.length === 0 && publicAccess === 'Enabled') {
          findings.push(this.finding(
            'Event Grid topic has no private endpoint configured',
            `Event Grid topic "${name}" has no private endpoint. All event publishing traffic traverses the public internet.`,
            'LOW',
            { topic: name, resourceGroup: rg },
            'Create a Private Endpoint in the publisher VNet and disable public access on the topic.',
            ['eventgrid', 'network', 'private-endpoint'],
          ));
        }

        // 4. Minimum TLS version
        const minTls = (topic as any).minimumTlsVersionAllowed ?? '1.0';
        if (minTls !== '1.2') {
          findings.push(this.finding(
            'Event Grid topic allows connections below TLS 1.2',
            `Event Grid topic "${name}" has minimum TLS version "${minTls}". Legacy TLS versions are vulnerable to downgrade attacks.`,
            'HIGH',
            { topic: name, resourceGroup: rg, minimumTlsVersion: minTls },
            'Set minimumTlsVersionAllowed to "1.2" on the Event Grid topic.',
            ['eventgrid', 'tls'],
          ));
        }
      }

      // Scan Domains
      const domains: any[] = [];
      for await (const d of egClient.domains.listBySubscription()) domains.push(d);

      for (const domain of domains) {
        const name = domain.name ?? 'unknown';
        const rg   = domain.id?.split('/')[4] ?? 'unknown';

        // 5. Public access on domain
        if ((domain.publicNetworkAccess ?? 'Enabled') === 'Enabled') {
          findings.push(this.finding(
            'Event Grid domain has public network access enabled',
            `Event Grid domain "${name}" is publicly accessible. Any internet host can publish events to domain topics if it obtains or guesses a valid access key.`,
            'HIGH',
            { domain: name, resourceGroup: rg },
            'Disable public network access on the Event Grid domain and use Private Endpoints for publisher access.',
            ['eventgrid', 'network', 'public-access'],
          ));
        }

        // 6. SAS auth on domain
        if (domain.disableLocalAuth !== true) {
          findings.push(this.finding(
            'Event Grid domain uses SAS key authentication instead of Microsoft Entra ID',
            `Event Grid domain "${name}" has local authentication (access keys) enabled. Publishers using shared keys have access to all topics in the domain.`,
            'MEDIUM',
            { domain: name, resourceGroup: rg },
            'Set disableLocalAuth to true on the domain and use Entra ID-based publisher identities for all domain topics.',
            ['eventgrid', 'authentication'],
          ));
        }
      }

      // Scan System Topics (check event subscriptions for insecure endpoints)
      const systemTopics: any[] = [];
      for await (const st of egClient.systemTopics.listBySubscription()) systemTopics.push(st);

      for (const topic of systemTopics) {
        const name = topic.name ?? 'unknown';
        const rg   = topic.id?.split('/')[4] ?? 'unknown';

        try {
          const subs: any[] = [];
          for await (const sub of egClient.systemTopicEventSubscriptions.listBySystemTopic(rg, name)) subs.push(sub);

          for (const sub of subs) {
            const endpoint = sub.destination?.endpointUrl ?? sub.destination?.endpointBaseUrl ?? '';
            if (endpoint.startsWith('http://')) {
              findings.push(this.finding(
                'Event Grid event subscription delivers events to an HTTP (non-HTTPS) endpoint',
                `Event Grid system topic "${name}" subscription "${sub.name}" delivers to HTTP endpoint "${endpoint}". Events (which may contain sensitive data) are transmitted in plaintext.`,
                'HIGH',
                { systemTopic: name, subscription: sub.name, endpoint, resourceGroup: rg },
                'Update the event subscription endpoint to an HTTPS URL. Configure webhook validation on the receiving endpoint.',
                ['eventgrid', 'encryption-in-transit'],
              ));
            }
          }
        } catch { /* optional */ }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Event Grid scan error',
        `Could not complete Event Grid scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Event Grid resources.',
      ));
    }

    return findings;
  }
}
