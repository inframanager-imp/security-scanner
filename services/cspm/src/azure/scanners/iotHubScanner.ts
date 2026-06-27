import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureIoTHubScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-IoTHub');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const iotClient = this.client.iotHub();

      const hubs: any[] = [];
      for await (const hub of iotClient.iotHubResource.listBySubscription()) hubs.push(hub);

      if (hubs.length === 0) return findings;

      for (const hub of hubs) {
        const name = hub.name ?? 'unknown';
        const rg   = hub.id?.split('/')[4] ?? 'unknown';
        const sku  = hub.sku?.name ?? 'S1';

        // 1. Minimum TLS version
        const minTls = hub.properties?.minTlsVersion ?? '1.0';
        if (minTls !== '1.2') {
          findings.push(this.finding(
            'Azure IoT Hub allows device connections below TLS 1.2',
            `IoT Hub "${name}" has minimum TLS version set to "${minTls}". IoT devices using TLS 1.0/1.1 are vulnerable to downgrade attacks and POODLE/BEAST exploits.`,
            'HIGH',
            { hub: name, resourceGroup: rg, minTlsVersion: minTls },
            'Set minTlsVersion to "1.2" on the IoT Hub. Update device firmware/SDK to use TLS 1.2 before enforcing.',
            ['iothub', 'tls', 'iot-security'],
          ));
        }

        // 2. Public network access enabled
        const publicAccess = hub.properties?.publicNetworkAccess ?? 'Enabled';
        if (publicAccess === 'Enabled') {
          findings.push(this.finding(
            'Azure IoT Hub has public network access enabled',
            `IoT Hub "${name}" is accessible from the public internet. Without IP filtering, any device can attempt to connect to the hub, increasing the attack surface for unauthorized device registration and data injection.`,
            'HIGH',
            { hub: name, resourceGroup: rg },
            'Enable IP filtering rules to allow only known device IP ranges. For backend service access, use Private Endpoints and disable public access.',
            ['iothub', 'network', 'public-access'],
          ));
        }

        // 3. IP filter rules — check for all-allow rule
        const ipFilterRules = hub.properties?.ipFilterRules ?? [];
        const hasOpenRule = ipFilterRules.some((r: any) =>
          r.action === 'Accept' && r.ipMask === '0.0.0.0/0',
        );
        if (hasOpenRule || (ipFilterRules.length === 0 && publicAccess === 'Enabled')) {
          findings.push(this.finding(
            'Azure IoT Hub has no IP filtering configured',
            `IoT Hub "${name}" allows connections from all IP addresses. Any internet host can attempt device-to-cloud communication without IP-based access control.`,
            'MEDIUM',
            { hub: name, resourceGroup: rg, ipFilterRules: ipFilterRules.length },
            'Configure IP filter rules to allow connections only from known device and service IP ranges. Block all other sources by default.',
            ['iothub', 'network', 'ip-filtering'],
          ));
        }

        // 4. Shared access policies — check for overly permissive policies
        const policies = hub.properties?.authorizationPolicies ?? [];
        for (const policy of policies) {
          const rights = policy.rights ?? '';
          const hasRegistryWrite = rights.includes('RegistryWrite') || rights.includes('RegistryReadWrite');
          const hasServiceConnect  = rights.includes('ServiceConnect');
          const hasDeviceConnect   = rights.includes('DeviceConnect');
          // A policy with all 3 is equivalent to the iothubowner key
          if (hasRegistryWrite && hasServiceConnect && hasDeviceConnect && policy.keyName !== 'iothubowner') {
            findings.push(this.finding(
              'Azure IoT Hub has a shared access policy with excessive permissions',
              `IoT Hub "${name}" shared access policy "${policy.keyName}" grants RegistryWrite, ServiceConnect, and DeviceConnect simultaneously. This is equivalent to full owner access and violates least privilege.`,
              'HIGH',
              { hub: name, resourceGroup: rg, policy: policy.keyName, rights },
              'Create separate, least-privilege shared access policies for each use case: device connections, backend services, and registry operations. Do not reuse the iothubowner key.',
              ['iothub', 'authentication', 'least-privilege'],
            ));
          }
        }

        // 5. No private endpoint
        const peConns = hub.properties?.privateEndpointConnections ?? [];
        if (peConns.length === 0) {
          findings.push(this.finding(
            'Azure IoT Hub has no private endpoint configured',
            `IoT Hub "${name}" has no private endpoint. Backend service traffic (Event Hub-compatible endpoint, built-in endpoints) flows over public internet.`,
            'MEDIUM',
            { hub: name, resourceGroup: rg },
            'Create a Private Endpoint for the IoT Hub to allow backend services to consume telemetry data without traversing the public internet.',
            ['iothub', 'network', 'private-endpoint'],
          ));
        }

        // 6. Defender for IoT — requires SecurityClient, deferred. Probe accessibility only.
        try {
          await iotClient.iotHubResource.getStats(rg, name);
        } catch { /* optional */ }

        // 7. Diagnostic logs
        try {
          const monitorClient = this.client.monitor();
          const settingsResult = await monitorClient.diagnosticSettings.list(hub.id!);
          const settings: any[] = settingsResult.value ?? [];
          const hasLogs = settings.some(s =>
            s.logs?.some((l: any) => l.enabled) || s.metrics?.some((m: any) => m.enabled),
          );
          if (!hasLogs) {
            findings.push(this.finding(
              'Azure IoT Hub has no diagnostic logs configured',
              `IoT Hub "${name}" has no diagnostic settings. Without logs, device authentication failures, connection events, and twin update operations cannot be audited for anomalous behavior.`,
              'MEDIUM',
              { hub: name, resourceGroup: rg },
              'Enable diagnostic settings to capture Connections, DeviceTelemetry, C2DCommands, and TwinQueries logs to a Log Analytics workspace.',
              ['iothub', 'logging'],
            ));
          }
        } catch { /* optional */ }

        // 8. Free / Basic SKU — limited security features
        if (sku === 'F1') {
          findings.push(this.finding(
            'Azure IoT Hub is using the Free tier',
            `IoT Hub "${name}" uses the Free tier (F1) which is limited to 1 unit, 8,000 messages/day, and no SLA. Not suitable for production IoT workloads.`,
            'MEDIUM',
            { hub: name, resourceGroup: rg, sku },
            'Upgrade to the Standard tier (S1/S2/S3) for production workloads to get SLA guarantees, higher message limits, and device management features.',
            ['iothub', 'sku'],
          ));
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure IoT Hub scan error',
        `Could not complete IoT Hub scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on IoT Hub resources.',
      ));
    }

    return findings;
  }
}
