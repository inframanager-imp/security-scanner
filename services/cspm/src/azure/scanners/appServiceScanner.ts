import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

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

          // Client certificate mode
          if (app.clientCertEnabled) {
            // good — mutual TLS
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
