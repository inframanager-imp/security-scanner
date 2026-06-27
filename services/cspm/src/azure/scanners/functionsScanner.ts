import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureFunctionsScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-Functions');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const webClient = this.client.webApps();

      const allApps: any[] = [];
      for await (const app of webClient.webApps.list()) allApps.push(app);

      // Filter to Function Apps only
      const funcApps = allApps.filter(a =>
        a.kind?.toLowerCase().includes('functionapp'),
      );

      if (funcApps.length === 0) return findings;

      for (const app of funcApps) {
        const name = app.name ?? 'unknown';
        const rg   = app.id?.split('/')[4] ?? 'unknown';

        let config: any = {};
        try {
          config = await webClient.webApps.getConfiguration(rg, name);
        } catch { /* optional */ }

        // 1. HTTPS not enforced
        if (!app.httpsOnly) {
          findings.push(this.finding(
            'Azure Function App does not enforce HTTPS',
            `Function App "${name}" allows HTTP connections. Function invocation URLs, auth tokens, and response data are transmitted in plaintext.`,
            'HIGH',
            { functionApp: name, resourceGroup: rg, httpsOnly: false },
            'Enable httpsOnly on the Function App to redirect all HTTP requests to HTTPS.',
            ['functions', 'encryption-in-transit'],
          ));
        }

        // 2. Minimum TLS version
        const minTls = config.minTlsVersion ?? '1.0';
        if (minTls !== '1.2') {
          findings.push(this.finding(
            'Azure Function App allows connections below TLS 1.2',
            `Function App "${name}" has minimum TLS version set to "${minTls}". TLS 1.0/1.1 are deprecated and vulnerable to downgrade attacks.`,
            'HIGH',
            { functionApp: name, resourceGroup: rg, minTlsVersion: minTls },
            'Set minTlsVersion to "1.2" in the Function App site configuration.',
            ['functions', 'tls'],
          ));
        }

        // 3. Anonymous auth — function with no auth level
        try {
          // Check if any function uses anonymous auth
          const funcs: any[] = [];
          for await (const fn of webClient.webApps.listFunctions(rg, name)) funcs.push(fn);
          const anonymousFuncs = funcs.filter(f =>
            f.config?.bindings?.some((b: any) =>
              b.type === 'httpTrigger' && b.authLevel === 'anonymous',
            ),
          );
          if (anonymousFuncs.length > 0) {
            findings.push(this.finding(
              'Azure Function App has HTTP triggers with anonymous authentication',
              `Function App "${name}" has ${anonymousFuncs.length} HTTP trigger(s) with authLevel set to "anonymous": ${anonymousFuncs.slice(0, 5).map(f => f.name).join(', ')}. Any internet user can invoke these functions without authentication.`,
              'HIGH',
              { functionApp: name, resourceGroup: rg, anonymousTriggers: anonymousFuncs.map(f => f.name) },
              'Set authLevel to "function" or "admin" on HTTP triggers, or use Entra ID authentication via APIM or Azure AD App Registration.',
              ['functions', 'authentication'],
            ));
          }
        } catch { /* listing functions may require additional permissions */ }

        // 4. Managed identity not assigned
        const hasManagedIdentity = app.identity?.type &&
          (app.identity.type.includes('SystemAssigned') || app.identity.type.includes('UserAssigned'));
        if (!hasManagedIdentity) {
          findings.push(this.finding(
            'Azure Function App has no managed identity assigned',
            `Function App "${name}" has no managed identity. Without managed identity, connections to storage, Key Vault, databases, and other services require storing credentials in application settings or connection strings.`,
            'MEDIUM',
            { functionApp: name, resourceGroup: rg },
            'Enable system-assigned managed identity on the Function App and update all service connections (Storage, Key Vault, Service Bus) to use Entra ID authentication.',
            ['functions', 'identity'],
          ));
        }

        // 5. CORS — wildcard origin
        const cors = config.cors;
        if (cors?.allowedOrigins?.includes('*')) {
          findings.push(this.finding(
            'Azure Function App has CORS configured to allow all origins (*)',
            `Function App "${name}" has CORS set to allow requests from any origin (*). This enables cross-site request forgery from malicious websites to invoke authenticated endpoints.`,
            'MEDIUM',
            { functionApp: name, resourceGroup: rg, allowedOrigins: cors.allowedOrigins },
            'Replace the wildcard (*) CORS origin with specific trusted domains. Remove all origins that are no longer in use.',
            ['functions', 'cors'],
          ));
        }

        // 6. Public network access — VNet integration
        const hasVnetIntegration = app.virtualNetworkSubnetId !== undefined && app.virtualNetworkSubnetId !== null;
        if (!hasVnetIntegration) {
          findings.push(this.finding(
            'Azure Function App is not integrated with a Virtual Network',
            `Function App "${name}" has no VNet integration. All outbound traffic (to backends, databases, storage) travels via public internet rather than a private network.`,
            'LOW',
            { functionApp: name, resourceGroup: rg },
            'Configure VNet integration to route Function App outbound traffic through a private subnet and enable access to VNet-connected services without public endpoints.',
            ['functions', 'network'],
          ));
        }

        // 7. Runtime version / EOL
        const linuxFxVersion = config.linuxFxVersion ?? '';
        if (linuxFxVersion.includes('PYTHON|3.7') || linuxFxVersion.includes('PYTHON|3.8') ||
            linuxFxVersion.includes('NODE|14') || linuxFxVersion.includes('NODE|12') ||
            linuxFxVersion.includes('JAVA|8')) {
          findings.push(this.finding(
            'Azure Function App uses an end-of-life runtime version',
            `Function App "${name}" runs an EOL language runtime: "${linuxFxVersion}". EOL runtimes no longer receive security patches and may have known unpatched vulnerabilities.`,
            'HIGH',
            { functionApp: name, resourceGroup: rg, runtime: linuxFxVersion },
            'Update the Function App to a supported runtime version. Test the updated function in a staging slot before swapping to production.',
            ['functions', 'eol-version'],
          ));
        }

        // 8. Remote debugging enabled
        if (config.remoteDebuggingEnabled) {
          findings.push(this.finding(
            'Azure Function App has remote debugging enabled',
            `Function App "${name}" has remote debugging enabled. Remote debugging opens an additional port and allows code inspection and breakpoint injection from external tools.`,
            'HIGH',
            { functionApp: name, resourceGroup: rg },
            'Disable remote debugging on all production Function Apps. Use Application Insights for distributed tracing and log-based debugging instead.',
            ['functions', 'debugging'],
          ));
        }

        // 9. Diagnostic logs
        try {
          const monitorClient = this.client.monitor();
          const settingsResult = await monitorClient.diagnosticSettings.list(app.id!);
          const settings: any[] = settingsResult.value ?? [];
          if (settings.length === 0 || !settings.some(s => s.logs?.some((l: any) => l.enabled))) {
            findings.push(this.finding(
              'Azure Function App has no diagnostic logs configured',
              `Function App "${name}" has no diagnostic settings. Without logs, function execution errors, authentication failures, and scaling events cannot be audited.`,
              'MEDIUM',
              { functionApp: name, resourceGroup: rg },
              'Enable diagnostic settings to stream FunctionAppLogs to a Log Analytics workspace.',
              ['functions', 'logging'],
            ));
          }
        } catch { /* optional */ }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Functions scan error',
        `Could not complete Function App scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on App Service / Function App resources.',
      ));
    }

    return findings;
  }
}
