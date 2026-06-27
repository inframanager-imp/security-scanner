import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureAppGatewayScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-AppGateway');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const networkClient = this.client.network();

      const gateways: any[] = [];
      for await (const gw of networkClient.applicationGateways.listAll()) gateways.push(gw);

      if (gateways.length === 0) return findings;

      for (const gw of gateways) {
        const name = gw.name ?? 'unknown';
        const rg   = gw.id?.split('/')[4] ?? 'unknown';
        const sku  = gw.sku?.name ?? 'Standard_v2';
        const tier = gw.sku?.tier ?? 'Standard_v2';

        // 1. WAF not enabled
        const wafConfig  = gw.webApplicationFirewallConfiguration;
        const isWafSku   = tier === 'WAF' || tier === 'WAF_v2';
        if (!isWafSku) {
          findings.push(this.finding(
            'Application Gateway is not using the WAF SKU',
            `Application Gateway "${name}" uses the "${tier}" SKU which does not include Web Application Firewall (WAF). Without WAF, published applications have no L7 protection against OWASP Top 10 attacks (SQLi, XSS, etc.).`,
            'HIGH',
            { gateway: name, resourceGroup: rg, sku },
            'Upgrade to the WAF_v2 SKU to enable Web Application Firewall on the Application Gateway.',
            ['appgateway', 'waf'],
          ));
        } else if (wafConfig?.enabled === false) {
          findings.push(this.finding(
            'Application Gateway WAF is disabled',
            `Application Gateway "${name}" has the WAF SKU but WAF is explicitly disabled. L7 threat protection is inactive.`,
            'HIGH',
            { gateway: name, resourceGroup: rg, sku },
            'Enable the WAF configuration on the Application Gateway.',
            ['appgateway', 'waf'],
          ));
        } else if (wafConfig?.firewallMode === 'Detection') {
          findings.push(this.finding(
            'Application Gateway WAF is in Detection mode, not Prevention mode',
            `Application Gateway "${name}" WAF is set to "Detection" mode. Malicious requests are logged but NOT blocked. This provides no active protection against attacks.`,
            'HIGH',
            { gateway: name, resourceGroup: rg, wafMode: 'Detection' },
            'Change the WAF firewall mode from "Detection" to "Prevention" on the Application Gateway policy.',
            ['appgateway', 'waf'],
          ));
        }

        // 2. HTTP listeners (non-HTTPS)
        const listeners = gw.httpListeners ?? [];
        const httpListeners = listeners.filter((l: any) => l.protocol === 'Http');
        const hasRedirectRule = (gw.redirectConfigurations ?? []).some((r: any) =>
          r.redirectType === 'Permanent' && r.targetListener !== undefined,
        );
        if (httpListeners.length > 0 && !hasRedirectRule) {
          findings.push(this.finding(
            'Application Gateway has HTTP listeners without HTTPS redirect',
            `Application Gateway "${name}" has ${httpListeners.length} HTTP listener(s) that serve traffic without HTTPS redirect. Client traffic is transmitted in plaintext.`,
            'HIGH',
            { gateway: name, resourceGroup: rg, httpListenerCount: httpListeners.length },
            'Add a redirect configuration to permanently redirect all HTTP listeners to their HTTPS counterparts. Remove plain HTTP listeners if no redirect is needed.',
            ['appgateway', 'encryption-in-transit'],
          ));
        }

        // 3. Weak TLS policy
        const sslPolicy = gw.sslPolicy;
        const minProtocol = sslPolicy?.minProtocolVersion ?? 'TLSv1_0';
        if (minProtocol === 'TLSv1_0' || minProtocol === 'TLSv1_1' || !sslPolicy) {
          findings.push(this.finding(
            'Application Gateway allows deprecated TLS versions',
            `Application Gateway "${name}" has minimum TLS protocol set to "${minProtocol || 'default (TLS 1.0)'}". TLS 1.0/1.1 are deprecated and vulnerable to protocol downgrade attacks.`,
            'HIGH',
            { gateway: name, resourceGroup: rg, minProtocol },
            'Set the SSL policy to "AppGwSslPolicy20220101" predefined policy or configure a custom policy with minimumProtocolVersion "TLSv1_2".',
            ['appgateway', 'tls'],
          ));
        }

        // 4. Backend without HTTPS (end-to-end TLS)
        const backendSettings = gw.backendHttpSettingsCollection ?? [];
        const httpBackends = backendSettings.filter((b: any) => b.protocol === 'Http');
        if (httpBackends.length > 0) {
          findings.push(this.finding(
            'Application Gateway communicates with backends over HTTP (not HTTPS)',
            `Application Gateway "${name}" has ${httpBackends.length} backend HTTP setting(s) using plain HTTP. Traffic between the gateway and backend servers is unencrypted, leaving internal traffic vulnerable to interception.`,
            'MEDIUM',
            { gateway: name, resourceGroup: rg, httpBackendCount: httpBackends.length },
            'Update backend HTTP settings to use HTTPS. Upload trusted CA certificates or use well-known CA-signed certificates on backend servers.',
            ['appgateway', 'end-to-end-tls'],
          ));
        }

        // 5. Backend probe not configured (health probe)
        const probes = gw.probes ?? [];
        if (probes.length === 0 && (gw.backendAddressPools ?? []).length > 0) {
          findings.push(this.finding(
            'Application Gateway has no custom health probes configured',
            `Application Gateway "${name}" uses only default health probes. Custom probes provide more accurate health detection and can prevent unhealthy backends from receiving traffic during incidents.`,
            'LOW',
            { gateway: name, resourceGroup: rg },
            'Configure custom health probes that validate backend application health at the application level rather than just TCP connectivity.',
            ['appgateway', 'availability'],
          ));
        }

        // 6. Managed identity not assigned
        const hasManagedIdentity = gw.identity?.type &&
          (gw.identity.type.includes('UserAssigned') || gw.identity.type.includes('SystemAssigned'));
        if (!hasManagedIdentity) {
          findings.push(this.finding(
            'Application Gateway has no managed identity assigned',
            `Application Gateway "${name}" has no managed identity. Without managed identity, TLS certificates cannot be stored in Key Vault and must be uploaded directly to the gateway.`,
            'MEDIUM',
            { gateway: name, resourceGroup: rg },
            'Assign a user-assigned managed identity to the Application Gateway and grant it "Key Vault Secrets User" role. Store TLS certificates in Key Vault and reference them from the gateway.',
            ['appgateway', 'identity'],
          ));
        }

        // 7. Basic SKU (v1)
        if (tier === 'Standard' || tier === 'WAF') {
          findings.push(this.finding(
            'Application Gateway is using the legacy v1 SKU',
            `Application Gateway "${name}" uses the v1 SKU ("${tier}"). The v1 SKU is on a retirement path and lacks autoscaling, zone redundancy, and modern WAF rule sets.`,
            'MEDIUM',
            { gateway: name, resourceGroup: rg, sku },
            'Migrate to Application Gateway v2 (Standard_v2 or WAF_v2) for autoscaling, zone redundancy, and the latest WAF OWASP CRS 3.2 rule set.',
            ['appgateway', 'sku'],
          ));
        }

        // 8. WAF policy not in Prevention and OWASP CRS version
        if (isWafSku && wafConfig?.enabled) {
          const crsVersion = wafConfig?.ruleSetVersion ?? '2.2.9';
          const outdatedCrs = ['2.2.9', '3.0', '3.1'].includes(crsVersion);
          if (outdatedCrs) {
            findings.push(this.finding(
              'Application Gateway WAF uses an outdated OWASP CRS rule set',
              `Application Gateway "${name}" WAF uses OWASP CRS version ${crsVersion}. Older CRS versions lack protection against newer attack patterns.`,
              'MEDIUM',
              { gateway: name, resourceGroup: rg, crsVersion },
              'Upgrade the WAF rule set to OWASP CRS 3.2 or later for improved detection of modern attack techniques.',
              ['appgateway', 'waf', 'crs'],
            ));
          }
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Application Gateway scan error',
        `Could not complete Application Gateway scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Application Gateway resources.',
      ));
    }

    return findings;
  }
}
