import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureServiceBusScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-ServiceBus');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const sbClient = this.client.serviceBus();

      const namespaces: any[] = [];
      for await (const ns of sbClient.namespaces.list()) namespaces.push(ns);

      if (namespaces.length === 0) return findings;

      for (const ns of namespaces) {
        const name = ns.name ?? 'unknown';
        const rg   = ns.id?.split('/')[4] ?? 'unknown';
        const sku  = ns.sku?.name ?? 'Basic';
        const tier = ns.sku?.tier ?? 'Basic';

        // 1. Public network access enabled
        const publicAccess = ns.publicNetworkAccess ?? 'Enabled';
        if (publicAccess === 'Enabled') {
          findings.push(this.finding(
            'Service Bus namespace has public network access enabled',
            `Service Bus namespace "${name}" is accessible from the public internet. This increases exposure to brute-force and unauthorized access attempts.`,
            'HIGH',
            { namespace: name, resourceGroup: rg, sku },
            'Set publicNetworkAccess to "Disabled" and use Private Endpoint to connect from VNet-integrated services.',
            ['servicebus', 'network', 'public-access'],
          ));
        }

        // 2. Minimum TLS version
        const minTls = (ns as any).minimumTlsVersion ?? '1.0';
        if (minTls !== '1.2') {
          findings.push(this.finding(
            'Service Bus namespace allows connections below TLS 1.2',
            `Service Bus namespace "${name}" has minimum TLS version "${minTls}". TLS 1.0/1.1 are deprecated and vulnerable to protocol downgrade attacks.`,
            'HIGH',
            { namespace: name, minimumTlsVersion: minTls, resourceGroup: rg },
            'Set minimumTlsVersion to "1.2" on the Service Bus namespace.',
            ['servicebus', 'tls'],
          ));
        }

        // 3. Local (SAS) authentication — prefer Entra ID
        const localAuthDisabled = (ns as any).disableLocalAuth === true;
        if (!localAuthDisabled && tier !== 'Basic') {
          findings.push(this.finding(
            'Service Bus namespace uses SAS key authentication instead of Microsoft Entra ID',
            `Service Bus namespace "${name}" has local SAS authentication enabled. SAS keys are shared secrets that cannot be scoped per user, do not support MFA, and must be manually rotated.`,
            'MEDIUM',
            { namespace: name, resourceGroup: rg, sku },
            'Set disableLocalAuth to true and migrate all clients to use Microsoft Entra ID (Managed Identity or Service Principal) for authentication.',
            ['servicebus', 'authentication'],
          ));
        }

        // 4. No private endpoint (for Standard/Premium)
        if (tier !== 'Basic') {
          try {
            const peConns: any[] = [];
            for await (const pe of sbClient.privateEndpointConnections.list(rg, name)) peConns.push(pe);
            if (peConns.length === 0 && publicAccess === 'Enabled') {
              findings.push(this.finding(
                'Service Bus namespace has no private endpoint configured',
                `Service Bus namespace "${name}" has no private endpoint. All traffic travels over the public internet even if network rules exist.`,
                'MEDIUM',
                { namespace: name, resourceGroup: rg },
                'Create a Private Endpoint in the VNet used by consuming services and disable public network access.',
                ['servicebus', 'network', 'private-endpoint'],
              ));
            }
          } catch { /* optional check */ }
        }

        // 5. Diagnostic logs not enabled
        try {
          const monitorClient = this.client.monitor();
          const settingsResult = await monitorClient.diagnosticSettings.list(ns.id!);
          const settings: any[] = settingsResult.value ?? [];
          const hasLogs = settings.some(s =>
            s.logs?.some((l: any) => l.enabled) || s.metrics?.some((m: any) => m.enabled),
          );
          if (!hasLogs) {
            findings.push(this.finding(
              'Service Bus namespace has no diagnostic logs configured',
              `Service Bus namespace "${name}" has no diagnostic settings. Without logs, unauthorized access, message processing failures, and anomalies cannot be detected or investigated.`,
              'MEDIUM',
              { namespace: name, resourceGroup: rg },
              'Enable diagnostic settings on the namespace to capture OperationalLogs and send them to a Log Analytics workspace or Storage Account.',
              ['servicebus', 'logging'],
            ));
          }
        } catch { /* monitor optional */ }

        // 6. Basic SKU — no VNET integration, no private endpoints, no geo-disaster recovery
        if (sku === 'Basic') {
          findings.push(this.finding(
            'Service Bus namespace is using the Basic SKU',
            `Service Bus namespace "${name}" uses the Basic SKU which does not support topics, VNET integration, private endpoints, or geo-disaster recovery. Not suitable for production messaging workloads.`,
            'LOW',
            { namespace: name, resourceGroup: rg, sku },
            'Upgrade to Standard SKU for topics/subscriptions and message sessions, or Premium for full isolation, VNET support, and geo-disaster recovery.',
            ['servicebus', 'sku', 'availability'],
          ));
        }

        // 7. Geo-disaster recovery not configured (Premium only)
        if (sku === 'Premium') {
          try {
            const drConfigs: any[] = [];
            for await (const dr of sbClient.disasterRecoveryConfigs.list(rg, name)) drConfigs.push(dr);
            if (drConfigs.length === 0) {
              findings.push(this.finding(
                'Service Bus Premium namespace has no geo-disaster recovery configured',
                `Service Bus namespace "${name}" (Premium) has no geo-disaster recovery pairing. A regional outage will result in namespace unavailability until the region recovers.`,
                'MEDIUM',
                { namespace: name, resourceGroup: rg },
                'Configure geo-disaster recovery by pairing with a secondary namespace in a different Azure region.',
                ['servicebus', 'availability', 'geo-recovery'],
              ));
            }
          } catch { /* optional */ }
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Service Bus scan error',
        `Could not complete Service Bus scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Service Bus namespaces.',
      ));
    }

    return findings;
  }
}
