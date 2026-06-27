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
          findings.push(this.finding(
            'App Service allows HTTP traffic',
            `App Service "${name}" does not enforce HTTPS-only. Users may connect over unencrypted HTTP.`,
            'HIGH',
            { app: name, resourceGroup: rg },
            'Enable the "HTTPS Only" setting on the App Service.',
            ['appservice', 'tls'],
          ));
        }

        // Minimum TLS version
        try {
          const config = await webClient.webApps.getConfiguration(rg, name);
          const minTls = config.minTlsVersion ?? '1.0';
          if (minTls !== '1.2') {
            findings.push(this.finding(
              'App Service uses weak minimum TLS version',
              `App Service "${name}" minimum TLS version is ${minTls}. TLS 1.0/1.1 are deprecated.`,
              'MEDIUM',
              { app: name, minTls, resourceGroup: rg },
              'Set the minimum TLS version to 1.2 in the App Service TLS/SSL settings.',
              ['appservice', 'tls'],
            ));
          }

          // Client certificate mode
          if (app.clientCertEnabled) {
            // good — mutual TLS
          }

          // FTP state
          const ftpState = config.ftpsState ?? 'AllAllowed';
          if (ftpState === 'AllAllowed') {
            findings.push(this.finding(
              'App Service allows unencrypted FTP access',
              `App Service "${name}" FTP state is "AllAllowed", permitting plain-text FTP connections. Credentials and code are transmitted unencrypted.`,
              'HIGH',
              { app: name, ftpState, resourceGroup: rg },
              'Set FTP state to "FtpsOnly" or "Disabled". Use FTPS or deployment slots/GitHub Actions instead.',
              ['appservice', 'ftp'],
            ));
          }

          // Remote debugging
          if (config.remoteDebuggingEnabled) {
            findings.push(this.finding(
              'App Service remote debugging is enabled',
              `App Service "${name}" has remote debugging enabled. This opens a debug port that could be exploited.`,
              'HIGH',
              { app: name, resourceGroup: rg },
              'Disable remote debugging in the App Service configuration. Only enable it temporarily when needed.',
              ['appservice', 'debugging'],
            ));
          }

          // Managed identity
          const identity = app.identity;
          if (!identity || identity.type === 'None') {
            findings.push(this.finding(
              'App Service does not use managed identity',
              `App Service "${name}" does not have a managed identity. Applications must use stored credentials to authenticate to Azure services.`,
              'MEDIUM',
              { app: name, resourceGroup: rg },
              'Enable system-assigned managed identity so the app can authenticate to Key Vault, Storage, and other services without credentials in code.',
              ['appservice', 'identity'],
            ));
          }

          // Authentication not configured
          if (!app.siteConfig?.acrUseManagedIdentityCreds) {
            const authSettings = await webClient.webApps.getAuthSettings(rg, name);
            if (!authSettings.enabled) {
              findings.push(this.finding(
                'App Service authentication (Easy Auth) not configured',
                `App Service "${name}" does not have Azure AD authentication (Easy Auth) enabled. The application handles its own authentication without an extra layer of protection.`,
                'LOW',
                { app: name, resourceGroup: rg },
                'Consider enabling Easy Auth with Azure AD to add a platform-level authentication layer in front of the application.',
                ['appservice', 'authentication'],
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
