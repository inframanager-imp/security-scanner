import { ManagedIdentityCredential, TokenCredential, AccessToken, GetTokenOptions } from '@azure/identity';
import { createHttpHeaders } from '@azure/core-rest-pipeline';
import type { HttpClient as AzureHttpClient, PipelineRequest, PipelineResponse } from '@azure/core-rest-pipeline';
import * as https from 'https';
import * as http  from 'http';
import * as zlib  from 'zlib';
import * as qs    from 'querystring';

/**
 * Native HTTPS implementation of TokenCredential.
 * Bypasses @azure/msal-node / undici which has network issues on WSL.
 */
class NativeServicePrincipalCredential implements TokenCredential {
  private cache: AccessToken | null = null;

  constructor(
    private readonly tenantId:     string,
    private readonly clientId:     string,
    private readonly clientSecret: string,
  ) {}

  async getToken(scopes: string | string[], _options?: GetTokenOptions): Promise<AccessToken | null> {
    const scope = Array.isArray(scopes) ? scopes[0] : scopes;

    // Return cached token if still valid (with 60s buffer)
    if (this.cache && this.cache.expiresOnTimestamp > Date.now() + 60_000) {
      return this.cache;
    }

    const body = qs.stringify({
      grant_type:    'client_credentials',
      client_id:     this.clientId,
      client_secret: this.clientSecret,
      scope,
    });

    return new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'login.microsoftonline.com',
        path:     `/${this.tenantId}/oauth2/v2.0/token`,
        method:   'POST',
        headers:  {
          'Content-Type':   'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body),
        },
      }, (res) => {
        let data = '';
        res.on('data', (c: Buffer) => { data += c; });
        res.on('end', () => {
          try {
            const json = JSON.parse(data) as Record<string, unknown>;
            if (json.access_token) {
              const expiresIn = Number(json.expires_in ?? 3600);
              this.cache = {
                token:              String(json.access_token),
                expiresOnTimestamp: Date.now() + expiresIn * 1000,
              };
              resolve(this.cache);
            } else {
              reject(new Error(String(json.error_description ?? json.error ?? 'Token request failed')));
            }
          } catch (e) {
            reject(new Error('Invalid JSON response from Azure AD'));
          }
        });
      });
      req.on('error', reject);
      req.setTimeout(15000, () => { req.destroy(); reject(new Error('Azure AD token request timed out')); });
      req.write(body);
      req.end();
    });
  }
}
/**
 * Native Node.js HTTP client for Azure ARM SDKs.
 * Bypasses undici/fetch (which fails on WSL) by using Node.js built-in https module.
 */
class NativeNodeHttpClient implements AzureHttpClient {
  async sendRequest(request: PipelineRequest): Promise<PipelineResponse> {
    const url   = new URL(request.url);
    const isHttps = url.protocol === 'https:';
    const lib: typeof https | typeof http = isHttps ? https : http;

    const reqHeaders: Record<string, string> = request.headers.toJSON();

    let bodyBuffer: Buffer | undefined;
    const body = request.body;
    if (body != null) {
      if (typeof body === 'string')       bodyBuffer = Buffer.from(body, 'utf8');
      else if (Buffer.isBuffer(body))     bodyBuffer = body;
      else if (body instanceof ArrayBuffer) bodyBuffer = Buffer.from(body);
    }
    if (bodyBuffer) reqHeaders['content-length'] = String(bodyBuffer.byteLength);

    return new Promise<PipelineResponse>((resolve, reject) => {
      const options: https.RequestOptions = {
        hostname: url.hostname,
        port:     url.port ? Number(url.port) : (isHttps ? 443 : 80),
        path:     url.pathname + url.search,
        method:   request.method,
        headers:  reqHeaders,
      };

      const req = lib.request(options, (res) => {
        const chunks: Buffer[] = [];
        const enc = (res.headers['content-encoding'] ?? '').toLowerCase();
        let stream: import('stream').Readable = res;
        if      (enc === 'gzip')    stream = res.pipe(zlib.createGunzip());
        else if (enc === 'deflate') stream = res.pipe(zlib.createInflate());
        else if (enc === 'br')      stream = res.pipe(zlib.createBrotliDecompress());

        stream.on('data',  (c: Buffer) => chunks.push(c));
        stream.on('error', reject);
        stream.on('end', () => {
          const bodyText = Buffer.concat(chunks).toString('utf8');
          const responseHeaders = createHttpHeaders();
          for (const [k, v] of Object.entries(res.headers)) {
            if (v != null) responseHeaders.set(k, Array.isArray(v) ? v.join(', ') : String(v));
          }
          resolve({ status: res.statusCode ?? 200, headers: responseHeaders, bodyAsText: bodyText, request });
        });
      });

      req.on('error', reject);
      if (request.timeout) {
        req.setTimeout(request.timeout, () => { req.destroy(new Error(`Request timed out: ${request.url}`)); });
      }
      if (bodyBuffer) req.write(bodyBuffer);
      req.end();
    });
  }
}

const nativeHttpClient = new NativeNodeHttpClient();

import { AuthorizationManagementClient }  from '@azure/arm-authorization';
import { StorageManagementClient }        from '@azure/arm-storage';
import { ComputeManagementClient }        from '@azure/arm-compute';
import { SqlManagementClient }            from '@azure/arm-sql';
import { KeyVaultManagementClient }       from '@azure/arm-keyvault';
import { NetworkManagementClient }        from '@azure/arm-network';
import { WebSiteManagementClient }        from '@azure/arm-appservice';
import { ContainerServiceClient }         from '@azure/arm-containerservice';
import { ContainerRegistryManagementClient } from '@azure/arm-containerregistry';
import { ManagedServiceIdentityClient }   from '@azure/arm-msi';
import { MonitorClient }                  from '@azure/arm-monitor';
import { RedisManagementClient }          from '@azure/arm-rediscache';
import { ServiceBusManagementClient }     from '@azure/arm-servicebus';
import { EventHubManagementClient }       from '@azure/arm-eventhub';
import { PostgreSQLManagementFlexibleServerClient } from '@azure/arm-postgresql-flexible';
import { MySQLManagementFlexibleServerClient }      from '@azure/arm-mysql-flexible';
import { CognitiveServicesManagementClient }        from '@azure/arm-cognitiveservices';
import { ApiManagementClient }            from '@azure/arm-apimanagement';
import { ContainerAppsAPIClient }         from '@azure/arm-appcontainers';
import { AzureMachineLearningServicesManagementClient } from '@azure/arm-machinelearning';
import { DataFactoryManagementClient }    from '@azure/arm-datafactory';
import { SynapseManagementClient }        from '@azure/arm-synapse';
import { RecoveryServicesClient }         from '@azure/arm-recoveryservices';
import { OperationalInsightsManagementClient } from '@azure/arm-operationalinsights';
import { EventGridManagementClient }      from '@azure/arm-eventgrid';
import { IotHubClient }                   from '@azure/arm-iothub';
import { SearchManagementClient }         from '@azure/arm-search';
import { AutomationClient }               from '@azure/arm-automation';
import { CosmosDBManagementClient }       from '@azure/arm-cosmosdb';

export interface AzureClientOptions {
  subscriptionId: string;
  tenantId?:      string;
  clientId?:      string;
  clientSecret?:  string;
  authMethod:     'SERVICE_PRINCIPAL' | 'MANAGED_IDENTITY';
}

export class AzureClient {
  readonly subscriptionId: string;
  readonly credential: TokenCredential;

  constructor(opts: AzureClientOptions) {
    this.subscriptionId = opts.subscriptionId;

    if (opts.authMethod === 'MANAGED_IDENTITY') {
      this.credential = new ManagedIdentityCredential();
    } else {
      if (!opts.tenantId || !opts.clientId || !opts.clientSecret) {
        throw new Error('SERVICE_PRINCIPAL requires tenantId, clientId, and clientSecret');
      }
      this.credential = new NativeServicePrincipalCredential(
        opts.tenantId,
        opts.clientId,
        opts.clientSecret,
      );
    }
  }

  /** Verify credentials by fetching an AAD token */
  async verifyCredentials(): Promise<{ valid: boolean; error?: string }> {
    try {
      await this.credential.getToken('https://management.azure.com/.default');
      return { valid: true };
    } catch (err) {
      return { valid: false, error: (err as Error).message };
    }
  }

  private opts() { return { httpClient: nativeHttpClient }; }

  authorization()     { return new AuthorizationManagementClient(this.credential, this.subscriptionId, this.opts()); }
  storage()           { return new StorageManagementClient(this.credential, this.subscriptionId, this.opts()); }
  compute()           { return new ComputeManagementClient(this.credential, this.subscriptionId, this.opts()); }
  sql()               { return new SqlManagementClient(this.credential, this.subscriptionId, this.opts()); }
  keyVault()          { return new KeyVaultManagementClient(this.credential, this.subscriptionId, this.opts()); }
  network()           { return new NetworkManagementClient(this.credential, this.subscriptionId, this.opts()); }
  webApps()           { return new WebSiteManagementClient(this.credential, this.subscriptionId, this.opts()); }
  containerService()  { return new ContainerServiceClient(this.credential, this.subscriptionId, this.opts()); }
  containerRegistry() { return new ContainerRegistryManagementClient(this.credential, this.subscriptionId, this.opts()); }
  managedIdentity()   { return new ManagedServiceIdentityClient(this.credential, this.subscriptionId, this.opts()); }
  monitor()           { return new MonitorClient(this.credential, this.subscriptionId, this.opts()); }
  redis()             { return new RedisManagementClient(this.credential, this.subscriptionId, this.opts()); }
  serviceBus()        { return new ServiceBusManagementClient(this.credential, this.subscriptionId, this.opts()); }
  eventHub()          { return new EventHubManagementClient(this.credential, this.subscriptionId, this.opts()); }
  postgres()          { return new PostgreSQLManagementFlexibleServerClient(this.credential, this.subscriptionId, this.opts()); }
  mysql()             { return new MySQLManagementFlexibleServerClient(this.credential, this.subscriptionId, this.opts()); }
  cognitiveServices() { return new CognitiveServicesManagementClient(this.credential, this.subscriptionId, this.opts()); }
  apiManagement()     { return new ApiManagementClient(this.credential, this.subscriptionId, this.opts()); }
  containerApps()     { return new ContainerAppsAPIClient(this.credential, this.subscriptionId, this.opts()); }
  machineLearning()   { return new AzureMachineLearningServicesManagementClient(this.credential, this.subscriptionId, this.opts()); }
  dataFactory()       { return new DataFactoryManagementClient(this.credential, this.subscriptionId, this.opts()); }
  synapse()           { return new SynapseManagementClient(this.credential, this.subscriptionId, this.opts()); }
  recoveryServices()  { return new RecoveryServicesClient(this.credential, this.subscriptionId, this.opts()); }
  operationalInsights(){ return new OperationalInsightsManagementClient(this.credential, this.subscriptionId, this.opts()); }
  eventGrid()         { return new EventGridManagementClient(this.credential, this.subscriptionId, this.opts()); }
  iotHub()            { return new IotHubClient(this.credential, this.subscriptionId, this.opts()); }
  search()            { return new SearchManagementClient(this.credential, this.subscriptionId, this.opts()); }
  automation()        { return new AutomationClient(this.credential, this.subscriptionId, 'status'); }
  cosmos()            { return new CosmosDBManagementClient(this.credential, this.subscriptionId, this.opts()); }
}

export default AzureClient;
