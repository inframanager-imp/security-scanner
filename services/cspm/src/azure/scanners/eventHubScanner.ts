import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureEventHubScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-EventHub');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const ehClient = this.client.eventHub();

      const namespaces: any[] = [];
      for await (const ns of ehClient.namespaces.list()) namespaces.push(ns);

      if (namespaces.length === 0) return findings;

      for (const ns of namespaces) {
        const name = ns.name ?? 'unknown';
        const rg   = ns.id?.split('/')[4] ?? 'unknown';
        const sku  = ns.sku?.name ?? 'Basic';
        const tier = ns.sku?.tier ?? 'Basic';

        // 1. Public network access enabled
        const publicAccess = (ns as any).publicNetworkAccess ?? 'Enabled';
        if (publicAccess === 'Enabled') {
          findings.push(this.finding(
            'Event Hub namespace has public network access enabled',
            `Event Hub namespace "${name}" is accessible from the public internet. This increases the attack surface for data exfiltration and unauthorized access to event streams.`,
            'HIGH',
            { namespace: name, resourceGroup: rg, sku },
            'Set publicNetworkAccess to "Disabled" and use Private Endpoint to restrict access to internal VNet consumers.',
            ['eventhub', 'network', 'public-access'],
          ));
        }

        // 2. Minimum TLS version
        const minTls = (ns as any).minimumTlsVersion ?? '1.0';
        if (minTls !== '1.2') {
          findings.push(this.finding(
            'Event Hub namespace allows connections below TLS 1.2',
            `Event Hub namespace "${name}" accepts TLS versions below 1.2 (current minimum: "${minTls}"). TLS 1.0/1.1 are deprecated and susceptible to protocol downgrade attacks.`,
            'HIGH',
            { namespace: name, minimumTlsVersion: minTls, resourceGroup: rg },
            'Set minimumTlsVersion to "1.2" on the Event Hub namespace.',
            ['eventhub', 'tls'],
          ));
        }

        // 3. Local (SAS) authentication — prefer Entra ID
        const localAuthDisabled = (ns as any).disableLocalAuth === true;
        if (!localAuthDisabled) {
          findings.push(this.finding(
            'Event Hub namespace uses SAS key authentication instead of Microsoft Entra ID',
            `Event Hub namespace "${name}" has local SAS authentication enabled. SAS keys are long-lived shared secrets that cannot be scoped per identity and must be manually rotated.`,
            'MEDIUM',
            { namespace: name, resourceGroup: rg, sku },
            'Set disableLocalAuth to true and migrate all producers/consumers to use Microsoft Entra ID (Managed Identity or Service Principal).',
            ['eventhub', 'authentication'],
          ));
        }

        // 4. No private endpoint (Standard/Dedicated tiers)
        if (tier !== 'Basic') {
          try {
            const peConns: any[] = [];
            for await (const pe of ehClient.privateEndpointConnections.list(rg, name)) peConns.push(pe);
            if (peConns.length === 0 && publicAccess === 'Enabled') {
              findings.push(this.finding(
                'Event Hub namespace has no private endpoint configured',
                `Event Hub namespace "${name}" has no private endpoint. Traffic between consumers and the namespace travels over public infrastructure.`,
                'MEDIUM',
                { namespace: name, resourceGroup: rg },
                'Create a Private Endpoint in the consuming VNet and disable public network access.',
                ['eventhub', 'network', 'private-endpoint'],
              ));
            }
          } catch { /* optional */ }
        }

        // 5. Diagnostic logs not configured
        try {
          const monitorClient = this.client.monitor();
          const settingsResult = await monitorClient.diagnosticSettings.list(ns.id!);
          const settings: any[] = settingsResult.value ?? [];
          const hasLogs = settings.some(s =>
            s.logs?.some((l: any) => l.enabled) || s.metrics?.some((m: any) => m.enabled),
          );
          if (!hasLogs) {
            findings.push(this.finding(
              'Event Hub namespace has no diagnostic logs configured',
              `Event Hub namespace "${name}" has no diagnostic settings. Without logs, access anomalies, throttling events, and consumer group activity cannot be audited.`,
              'MEDIUM',
              { namespace: name, resourceGroup: rg },
              'Enable diagnostic settings to capture ArchiveLogs, OperationalLogs, and AutoScaleLogs and send to Log Analytics.',
              ['eventhub', 'logging'],
            ));
          }
        } catch { /* monitor optional */ }

        // 6. No capture configured on event hubs (data durability)
        try {
          const hubs: any[] = [];
          for await (const hub of ehClient.eventHubs.listByNamespace(rg, name)) hubs.push(hub);

          for (const hub of hubs) {
            const captureEnabled = hub.captureDescription?.enabled === true;
            if (!captureEnabled && tier !== 'Basic') {
              findings.push(this.finding(
                'Event Hub has no capture (archival) configured',
                `Event Hub "${hub.name}" in namespace "${name}" has no Capture enabled. Event data is ephemeral and lost after the retention period unless captured to Storage or Data Lake.`,
                'LOW',
                { eventHub: hub.name, namespace: name, resourceGroup: rg },
                'Enable Capture on the Event Hub to archive event data to Azure Blob Storage or Azure Data Lake Store for replay, compliance, and audit purposes.',
                ['eventhub', 'data-retention'],
              ));
            }
          }
        } catch { /* event hub list optional */ }

        // 7. Basic SKU limitations
        if (sku === 'Basic') {
          findings.push(this.finding(
            'Event Hub namespace is using the Basic SKU',
            `Event Hub namespace "${name}" uses the Basic SKU which does not support consumer groups beyond $Default, AMQP protocol over WebSockets, or VNET/firewall integration. Not suitable for production workloads.`,
            'LOW',
            { namespace: name, resourceGroup: rg, sku },
            'Upgrade to Standard or Premium SKU for consumer groups, VNET integration, private endpoints, and Kafka support.',
            ['eventhub', 'sku'],
          ));
        }

        // 8. Auto-inflate disabled on Standard (can cause throttling)
        if (sku === 'Standard' && ns.isAutoInflateEnabled === false) {
          const tus = ns.maximumThroughputUnits ?? 0;
          if (tus <= 10) {
            findings.push(this.finding(
              'Event Hub Standard namespace has auto-inflate disabled with low throughput units',
              `Event Hub namespace "${name}" has auto-inflate disabled and only ${tus} throughput units allocated. Under load spikes, messages will be throttled and producers may drop events.`,
              'LOW',
              { namespace: name, resourceGroup: rg, maximumThroughputUnits: tus },
              'Enable auto-inflate with an appropriate maximum throughput unit limit to prevent message loss during traffic spikes.',
              ['eventhub', 'availability'],
            ));
          }
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Event Hub scan error',
        `Could not complete Event Hub scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Event Hub namespaces.',
      ));
    }

    return findings;
  }
}
