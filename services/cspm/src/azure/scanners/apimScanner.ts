import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureAPIMScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-APIM');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const apimClient = this.client.apiManagement();

      const services: any[] = [];
      for await (const svc of apimClient.apiManagementService.list()) services.push(svc);

      if (services.length === 0) return findings;

      for (const svc of services) {
        const name = svc.name ?? 'unknown';
        const rg   = svc.id?.split('/')[4] ?? 'unknown';
        const sku  = svc.sku?.name ?? 'Developer';
        const tier = sku;

        // 1. HTTP (non-HTTPS) gateway URL accessible
        const gatewayUrl = svc.gatewayUrl ?? '';
        if (gatewayUrl.startsWith('http://')) {
          findings.push(this.finding(
            'API Management gateway exposes an HTTP (non-HTTPS) endpoint',
            `API Management service "${name}" has an HTTP gateway URL (${gatewayUrl}). APIs published via HTTP transmit client requests and responses, including auth tokens, in plaintext.`,
            'HIGH',
            { service: name, resourceGroup: rg, gatewayUrl },
            'Enforce HTTPS-only on the API Management gateway. Disable HTTP by setting customProperties["Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10"] and enforcing redirect to HTTPS.',
            ['apim', 'encryption-in-transit', 'http'],
          ));
        }

        // 2. Minimum TLS version check via custom properties
        const customProps = svc.customProperties ?? {};
        const tls10Enabled = customProps['Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10'] === 'true';
        const tls11Enabled = customProps['Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11'] === 'true';
        const ssl30Enabled = customProps['Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Ssl30'] === 'true';
        if (tls10Enabled || tls11Enabled || ssl30Enabled) {
          findings.push(this.finding(
            'API Management gateway allows deprecated TLS/SSL protocols',
            `API Management service "${name}" has legacy protocol(s) enabled: ${[
              ssl30Enabled && 'SSL 3.0',
              tls10Enabled && 'TLS 1.0',
              tls11Enabled && 'TLS 1.1',
            ].filter(Boolean).join(', ')}. These protocols are vulnerable to POODLE, BEAST, and related attacks.`,
            'HIGH',
            { service: name, resourceGroup: rg, tls10Enabled, tls11Enabled, ssl30Enabled },
            'Disable SSL 3.0, TLS 1.0, and TLS 1.1 via APIM custom properties. Enforce TLS 1.2 as the minimum protocol version.',
            ['apim', 'tls'],
          ));
        }

        // 3. No Virtual Network integration (for Consumption/Developer, flag as informational)
        const vnetType = svc.virtualNetworkType ?? 'None';
        if (vnetType === 'None' && tier !== 'Consumption') {
          findings.push(this.finding(
            'API Management service has no Virtual Network integration',
            `API Management service "${name}" (${sku}) is not integrated with a Virtual Network. Backend APIs and internal services are reached over public internet, increasing exposure.`,
            'MEDIUM',
            { service: name, resourceGroup: rg, sku, virtualNetworkType: vnetType },
            'Configure Virtual Network integration in External or Internal mode to route backend traffic through a VNet and restrict access to the developer portal and gateway.',
            ['apim', 'network', 'vnet'],
          ));
        }

        // 4. Public endpoint not disabled (Internal VNet mode preferred)
        if (vnetType === 'None') {
          findings.push(this.finding(
            'API Management service gateway is publicly accessible',
            `API Management service "${name}" has no VNet integration, making the gateway publicly accessible. Any actor on the internet can probe published APIs.`,
            'MEDIUM',
            { service: name, resourceGroup: rg, sku },
            'Integrate APIM with a VNet in Internal mode to expose the gateway only within the VNet. Place Azure Front Door or Application Gateway in front for external traffic with WAF enabled.',
            ['apim', 'network', 'public-access'],
          ));
        }

        // 5. WAF / Azure Front Door not in front (informational for externally-exposed APIM)
        // We detect this by checking if a hostname configuration references a CDN/Front Door CNAME
        const hostnames = svc.hostnameConfigurations ?? [];
        const hasCdnOrWaf = hostnames.some((h: any) =>
          h.hostName?.includes('azurefd.net') ||
          h.hostName?.includes('trafficmanager.net') ||
          h.hostName?.includes('cloudapp.azure.com'),
        );
        if (!hasCdnOrWaf && vnetType === 'None') {
          findings.push(this.finding(
            'API Management service has no WAF or Azure Front Door in front',
            `API Management service "${name}" appears to be directly internet-exposed without Azure Front Door or Application Gateway with WAF. Published APIs lack L7 protection against injection, DDoS, and bot attacks.`,
            'MEDIUM',
            { service: name, resourceGroup: rg, sku },
            'Place Azure Front Door (with WAF policy) or Azure Application Gateway (WAF v2) in front of the APIM gateway. Configure APIM to accept traffic only from the Front Door or AppGW IP ranges.',
            ['apim', 'waf', 'network'],
          ));
        }

        // 6. Backend certificates — check if backend SSL validation is disabled
        try {
          const backends: any[] = [];
          for await (const be of apimClient.backend.listByService(rg, name)) backends.push(be);

          const insecureBackends = backends.filter(b =>
            b.tls?.validateCertificateChain === false ||
            b.tls?.validateCertificateName === false,
          );
          if (insecureBackends.length > 0) {
            findings.push(this.finding(
              'API Management has backends with SSL certificate validation disabled',
              `${insecureBackends.length} backend(s) in APIM service "${name}" have certificate chain or name validation disabled. This allows man-in-the-middle attacks on backend API traffic.`,
              'HIGH',
              { service: name, resourceGroup: rg, affectedBackends: insecureBackends.map(b => b.name) },
              'Enable validateCertificateChain and validateCertificateName on all backends. Use trusted certificates on backend services. Upload self-signed CA certs to APIM if using private PKI.',
              ['apim', 'backend', 'tls'],
            ));
          }
        } catch { /* optional */ }

        // 7. Named values containing plaintext secrets
        try {
          const namedValues: any[] = [];
          for await (const nv of apimClient.namedValue.listByService(rg, name)) namedValues.push(nv);

          const plaintextSecrets = namedValues.filter(nv =>
            nv.secret === false &&
            (nv.displayName?.toLowerCase().includes('key') ||
             nv.displayName?.toLowerCase().includes('secret') ||
             nv.displayName?.toLowerCase().includes('password') ||
             nv.displayName?.toLowerCase().includes('token')),
          );
          if (plaintextSecrets.length > 0) {
            findings.push(this.finding(
              'API Management has named values with potential plaintext secrets',
              `${plaintextSecrets.length} named value(s) in APIM service "${name}" appear to contain secrets but are stored as plaintext (not marked as secret or Key Vault reference): ${plaintextSecrets.slice(0, 5).map(nv => nv.displayName).join(', ')}.`,
              'HIGH',
              { service: name, resourceGroup: rg, count: plaintextSecrets.length },
              'Convert sensitive named values to "secret" type and back them with Azure Key Vault. Never store API keys, passwords, or tokens as plaintext named values.',
              ['apim', 'secrets', 'key-vault'],
            ));
          }
        } catch { /* optional */ }

        // 8. Managed identity not assigned
        const hasManagedIdentity = svc.identity?.type &&
          (svc.identity.type.includes('SystemAssigned') || svc.identity.type.includes('UserAssigned'));
        if (!hasManagedIdentity) {
          findings.push(this.finding(
            'API Management service has no managed identity assigned',
            `API Management service "${name}" has no managed identity. Without managed identity, Key Vault access for named values and backend certificate retrieval requires storing credentials explicitly.`,
            'MEDIUM',
            { service: name, resourceGroup: rg },
            'Assign a system-assigned managed identity to the APIM service. Grant it Key Vault Secrets User role to securely retrieve named values and certificates from Key Vault.',
            ['apim', 'identity'],
          ));
        }

        // 9. Diagnostic logs not configured
        try {
          const monitorClient = this.client.monitor();
          const settingsResult = await monitorClient.diagnosticSettings.list(svc.id!);
          const settings: any[] = settingsResult.value ?? [];
          const hasLogs = settings.some(s =>
            s.logs?.some((l: any) => l.enabled) || s.metrics?.some((m: any) => m.enabled),
          );
          if (!hasLogs) {
            findings.push(this.finding(
              'API Management service has no diagnostic logs configured',
              `APIM service "${name}" has no diagnostic settings. Without logs, unauthorized API calls, policy violations, and backend errors cannot be audited or detected.`,
              'MEDIUM',
              { service: name, resourceGroup: rg },
              'Enable diagnostic settings on the APIM service to send GatewayLogs and metrics to a Log Analytics workspace.',
              ['apim', 'logging'],
            ));
          }
        } catch { /* optional */ }

        // 10. Developer/Consumption SKU in production pattern (informational)
        if (tier === 'Developer') {
          findings.push(this.finding(
            'API Management service is using the Developer SKU',
            `API Management service "${name}" uses the Developer SKU which has no SLA and is intended for non-production use only. Using it in production risks unplanned downtime.`,
            'LOW',
            { service: name, resourceGroup: rg, sku },
            'Upgrade to Standard or Premium SKU for production workloads to benefit from SLA guarantees and multi-region deployment capabilities.',
            ['apim', 'sku'],
          ));
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure API Management scan error',
        `Could not complete API Management scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on API Management resources.',
      ));
    }

    return findings;
  }
}
