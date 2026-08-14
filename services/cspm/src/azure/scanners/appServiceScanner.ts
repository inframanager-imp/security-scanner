// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

const LATEST_JAVA_VERSION = '17';
const LATEST_PHP_VERSION = '8.2';
const LATEST_PYTHON_VERSION = '3.12';

export class AzureAppServiceScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-AppService');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const webClient = this.client.webApps();

    try {
      const apps: any[] = [];
      for await (const app of webClient.webApps.list()) apps.push(app);

      for (const app of apps) {
        const name = app.name ?? 'unknown';
        const rg   = app.id?.split('/')[4] ?? 'unknown';

        // HTTPS-only
        if (!app.httpsOnly) {
          findings.push(this.emit(
            'azure_appservice_https_only_enforced',
            { app: name, resourceGroup: rg },
            { message: `App Service "${name}" does not enforce HTTPS-only. Users may connect over unencrypted HTTP.` },
          ));
        }

        // Client certificate mode (app_client_certificates_on)
        if (app.clientCertMode !== 'Required') {
          findings.push(this.emit(
            'app_client_certificates_on',
            { app: name, resourceGroup: rg, clientCertMode: app.clientCertMode ?? 'Disabled' },
            { message: `App Service "${name}" does not require client certificates (clientCertMode is "${app.clientCertMode ?? 'Disabled'}"). Mutual TLS is not enforced for inbound requests.` },
          ));
        }

        // Minimum TLS version
        try {
          const config = await webClient.webApps.getConfiguration(rg, name);
          const minTls = config.minTlsVersion ?? '1.0';
          if (minTls !== '1.2') {
            findings.push(this.emit(
              'azure_appservice_minimum_tls_version_12',
              { app: name, minTls, resourceGroup: rg },
              { message: `App Service "${name}" minimum TLS version is ${minTls}. TLS 1.0/1.1 are deprecated.` },
            ));
          }

          // HTTP/2.0 (app_ensure_using_http20)
          if (!config.http20Enabled) {
            findings.push(this.emit(
              'app_ensure_using_http20',
              { app: name, resourceGroup: rg },
              { message: `App Service "${name}" does not have HTTP/2.0 enabled.` },
            ));
          }

          // FTP state
          const ftpState = config.ftpsState ?? 'AllAllowed';
          if (ftpState === 'AllAllowed') {
            findings.push(this.emit(
              'azure_appservice_ftp_disabled_or_ftps_only',
              { app: name, ftpState, resourceGroup: rg },
              { message: `App Service "${name}" FTP state is "AllAllowed", permitting plain-text FTP connections. Credentials and code are transmitted unencrypted.` },
            ));
          }

          // Remote debugging
          if (config.remoteDebuggingEnabled) {
            findings.push(this.emit(
              'azure_appservice_remote_debugging_disabled',
              { app: name, resourceGroup: rg },
              { message: `App Service "${name}" has remote debugging enabled. This opens a debug port that could be exploited.` },
            ));
          }

          // Managed identity
          const identity = app.identity;
          if (!identity || identity.type === 'None') {
            findings.push(this.emit(
              'azure_appservice_managed_identity_configured',
              { app: name, resourceGroup: rg },
              { message: `App Service "${name}" does not have a managed identity. Applications must use stored credentials to authenticate to Azure services.` },
            ));
          }

          // Authentication not configured
          if (!app.siteConfig?.acrUseManagedIdentityCreds) {
            const authSettings = await webClient.webApps.getAuthSettings(rg, name);
            if (!authSettings.enabled) {
              findings.push(this.emit(
                'azure_appservice_authentication_configured',
                { app: name, resourceGroup: rg },
                { message: `App Service "${name}" does not have Azure AD authentication (Easy Auth) enabled. The application handles its own authentication without an extra layer of protection.` },
              ));
            }
          }

          // HTTP logs (app_http_logs_enabled) — web apps only, not Function Apps
          if (!(app.kind ?? '').toLowerCase().includes('functionapp')) {
            try {
              const monitorClient = this.client.monitor();
              const settingsResult = await monitorClient.diagnosticSettings.list(app.id!);
              const settings: any[] = settingsResult.value ?? [];
              const hasHttpLogs = settings.some((s: any) =>
                s.logs?.some((l: any) => l.enabled && (l.category === 'AppServiceHTTPLogs' || l.categoryGroup === 'allLogs')),
              );
              if (!hasHttpLogs) {
                findings.push(this.emit(
                  'app_http_logs_enabled',
                  { app: name, resourceGroup: rg },
                  { message: `App Service "${name}" does not have HTTP request logging enabled in diagnostic settings. Web access events are not captured for audit.` },
                ));
              }
            } catch { /* optional */ }
          }

          // Runtime language versions (Java / PHP / Python)
          const linuxFxVersion: string = (config.linuxFxVersion ?? '').toUpperCase();

          if (linuxFxVersion.includes('JAVA') || config.javaVersion) {
            const usesLatestJava = linuxFxVersion.includes(`JAVA|${LATEST_JAVA_VERSION}`) || config.javaVersion === LATEST_JAVA_VERSION;
            if (!usesLatestJava) {
              const current = config.javaVersion ? `java${config.javaVersion}` : config.linuxFxVersion;
              findings.push(this.emit(
                'app_ensure_java_version_is_latest',
                { app: name, resourceGroup: rg, javaVersion: current },
                { message: `App Service "${name}" Java version is set to "${current}", but should be set to Java ${LATEST_JAVA_VERSION}.` },
              ));
            }
          }

          if (linuxFxVersion.includes('PHP') || config.phpVersion) {
            const current = config.phpVersion || config.linuxFxVersion;
            const usesLatestPhp = linuxFxVersion.includes(LATEST_PHP_VERSION) || config.phpVersion === LATEST_PHP_VERSION;
            if (!usesLatestPhp) {
              findings.push(this.emit(
                'app_ensure_php_version_is_latest',
                { app: name, resourceGroup: rg, phpVersion: current },
                { message: `App Service "${name}" PHP version is set to "${current}". The latest supported version is ${LATEST_PHP_VERSION}.` },
              ));
            }
          }

          if (linuxFxVersion.includes('PYTHON') || config.pythonVersion) {
            const current = config.pythonVersion || config.linuxFxVersion;
            const usesLatestPython = linuxFxVersion.includes(LATEST_PYTHON_VERSION) || config.pythonVersion === LATEST_PYTHON_VERSION;
            if (!usesLatestPython) {
              findings.push(this.emit(
                'app_ensure_python_version_is_latest',
                { app: name, resourceGroup: rg, pythonVersion: current },
                { message: `App Service "${name}" Python version is set to "${current}". The latest supported version is ${LATEST_PYTHON_VERSION}.` },
              ));
            }
          }
        } catch { /* skip config errors per app */ }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure App Service scan error',
        `Could not complete App Service scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Website Contributor or Reader permissions.',
      ));
    }

    return findings;
  }
}
