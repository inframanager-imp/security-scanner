// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
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
          findings.push(this.emit(
            'azure_functions_https_only_enforced',
            { functionApp: name, resourceGroup: rg, httpsOnly: false },
            { message: `Function App "${name}" allows HTTP connections. Function invocation URLs, auth tokens, and response data are transmitted in plaintext.` },
          ));
        }

        // 2. Minimum TLS version
        const minTls = config.minTlsVersion ?? '1.0';
        if (minTls !== '1.2') {
          findings.push(this.emit(
            'azure_functions_minimum_tls_version_12',
            { functionApp: name, resourceGroup: rg, minTlsVersion: minTls },
            { message: `Function App "${name}" has minimum TLS version set to "${minTls}". TLS 1.0/1.1 are deprecated and vulnerable to downgrade attacks.` },
          ));
        }

        // 3. Anonymous auth — function with no auth level; also gathers per-function
        //    data reused below for the function-keys check.
        let funcs: any[] = [];
        try {
          for await (const fn of webClient.webApps.listFunctions(rg, name)) funcs.push(fn);
          const anonymousFuncs = funcs.filter(f =>
            f.config?.bindings?.some((b: any) =>
              b.type === 'httpTrigger' && b.authLevel === 'anonymous',
            ),
          );
          if (anonymousFuncs.length > 0) {
            findings.push(this.emit(
              'azure_functions_no_anonymous_http_triggers',
              { functionApp: name, resourceGroup: rg, anonymousTriggers: anonymousFuncs.map(f => f.name) },
              { message: `Function App "${name}" has ${anonymousFuncs.length} HTTP trigger(s) with authLevel set to "anonymous": ${anonymousFuncs.slice(0, 5).map(f => f.name).join(', ')}. Any internet user can invoke these functions without authentication.` },
            ));
          }
        } catch { /* listing functions may require additional permissions */ }

        // app_function_access_keys_configured — HTTP-triggered functions should
        // have at least one function-level access key configured.
        try {
          const httpTriggerFuncs = funcs.filter(f =>
            f.config?.bindings?.some((b: any) => b.type === 'httpTrigger'),
          );
          const funcsWithoutKeys: string[] = [];
          for (const fn of httpTriggerFuncs) {
            const fnName = (fn.name ?? '').split('/').pop() ?? fn.name;
            try {
              const keysResult = await webClient.webApps.listFunctionKeys(rg, name, fnName);
              const keys = keysResult.properties ?? {};
              if (Object.keys(keys).length === 0) {
                funcsWithoutKeys.push(fnName);
              }
            } catch {
              funcsWithoutKeys.push(fnName);
            }
          }
          if (httpTriggerFuncs.length > 0 && funcsWithoutKeys.length > 0) {
            findings.push(this.emit(
              'app_function_access_keys_configured',
              { functionApp: name, resourceGroup: rg, functionsWithoutKeys: funcsWithoutKeys.slice(0, 10) },
              { message: `Function App "${name}" has ${funcsWithoutKeys.length} HTTP-triggered function(s) with no function-level access key configured: ${funcsWithoutKeys.slice(0, 5).join(', ')}.` },
            ));
          }
        } catch { /* function key listing optional */ }

        // 4. Managed identity not assigned
        const hasManagedIdentity = app.identity?.type &&
          (app.identity.type.includes('SystemAssigned') || app.identity.type.includes('UserAssigned'));
        if (!hasManagedIdentity) {
          findings.push(this.emit(
            'azure_functions_managed_identity_configured',
            { functionApp: name, resourceGroup: rg },
            { message: `Function App "${name}" has no managed identity. Without managed identity, connections to storage, Key Vault, databases, and other services require storing credentials in application settings or connection strings.` },
          ));
        }

        // 5. CORS — wildcard origin
        const cors = config.cors;
        if (cors?.allowedOrigins?.includes('*')) {
          findings.push(this.emit(
            'azure_functions_cors_not_wildcard',
            { functionApp: name, resourceGroup: rg, allowedOrigins: cors.allowedOrigins },
            { message: `Function App "${name}" has CORS set to allow requests from any origin (*). This enables cross-site request forgery from malicious websites to invoke authenticated endpoints.` },
          ));
        }

        // 6. Public network access — VNet integration
        const hasVnetIntegration = app.virtualNetworkSubnetId !== undefined && app.virtualNetworkSubnetId !== null;
        if (!hasVnetIntegration) {
          findings.push(this.emit(
            'azure_functions_vnet_integration_enabled',
            { functionApp: name, resourceGroup: rg },
            { message: `Function App "${name}" has no VNet integration. All outbound traffic (to backends, databases, storage) travels via public internet rather than a private network.` },
          ));
        }

        // app_function_not_publicly_accessible — publicNetworkAccess should be
        // disabled, or access restrictions/private endpoints should scope inbound traffic.
        if (app.publicNetworkAccess !== 'Disabled') {
          findings.push(this.emit(
            'app_function_not_publicly_accessible',
            { functionApp: name, resourceGroup: rg, publicNetworkAccess: app.publicNetworkAccess ?? 'Enabled' },
            { message: `Function App "${name}" is publicly accessible (publicNetworkAccess is "${app.publicNetworkAccess ?? 'Enabled'}"). Restrict access via IP-based access restrictions or a Private Endpoint.` },
          ));
        }

        // 7. Runtime version / EOL
        const linuxFxVersion = config.linuxFxVersion ?? '';
        if (linuxFxVersion.includes('PYTHON|3.7') || linuxFxVersion.includes('PYTHON|3.8') ||
            linuxFxVersion.includes('NODE|14') || linuxFxVersion.includes('NODE|12') ||
            linuxFxVersion.includes('JAVA|8')) {
          findings.push(this.emit(
            'azure_functions_runtime_not_eol',
            { functionApp: name, resourceGroup: rg, runtime: linuxFxVersion },
            { message: `Function App "${name}" runs an EOL language runtime: "${linuxFxVersion}". EOL runtimes no longer receive security patches and may have known unpatched vulnerabilities.` },
          ));
        }

        // 8. Remote debugging enabled
        if (config.remoteDebuggingEnabled) {
          findings.push(this.emit(
            'azure_functions_remote_debugging_disabled',
            { functionApp: name, resourceGroup: rg },
            { message: `Function App "${name}" has remote debugging enabled. Remote debugging opens an additional port and allows code inspection and breakpoint injection from external tools.` },
          ));
        }

        // app_function_ftps_deployment_disabled
        const ftpsState = config.ftpsState ?? 'AllAllowed';
        if (ftpsState !== 'Disabled') {
          findings.push(this.emit(
            'app_function_ftps_deployment_disabled',
            { functionApp: name, resourceGroup: rg, ftpsState },
            { message: `Function App "${name}" has ${ftpsState === 'AllAllowed' ? 'FTP' : ftpsState === 'FtpsOnly' ? 'FTPS' : 'FTP or FTPS'} deployment enabled. Deployment credentials and code are exposed to an additional protocol surface.` },
          ));
        }

        // 9. Diagnostic logs
        try {
          const monitorClient = this.client.monitor();
          const settingsResult = await monitorClient.diagnosticSettings.list(app.id!);
          const settings: any[] = settingsResult.value ?? [];
          if (settings.length === 0 || !settings.some(s => s.logs?.some((l: any) => l.enabled))) {
            findings.push(this.emit(
              'azure_functions_diagnostic_logs_configured',
              { functionApp: name, resourceGroup: rg },
              { message: `Function App "${name}" has no diagnostic settings. Without logs, function execution errors, authentication failures, and scaling events cannot be audited.` },
            ));
          }
        } catch { /* optional */ }

        // app_function_application_insights_enabled
        try {
          const appSettingsResult = await webClient.webApps.listApplicationSettings(rg, name);
          const envVars: Record<string, string> = appSettingsResult.properties ?? {};
          const hasAppInsights = Boolean(
            envVars['APPINSIGHTS_INSTRUMENTATIONKEY'] || envVars['APPLICATIONINSIGHTS_CONNECTION_STRING'],
          );
          if (!hasAppInsights) {
            findings.push(this.emit(
              'app_function_application_insights_enabled',
              { functionApp: name, resourceGroup: rg },
              { message: `Function App "${name}" is not sending telemetry to Application Insights. Execution failures and performance data are not being captured.` },
            ));
          }
        } catch { /* application settings listing optional */ }
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
