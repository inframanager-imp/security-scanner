import { AzureBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class AzureContainerAppsScanner extends AzureBaseScanner {
  constructor(client: import('../client').AzureClient) {
    super(client, 'Azure-ContainerApps');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const caClient = this.client.containerApps();

      // Scan Container App Environments
      const environments: any[] = [];
      for await (const env of caClient.managedEnvironments.listBySubscription()) environments.push(env);

      for (const env of environments) {
        const envName = env.name ?? 'unknown';
        const rg = env.id?.split('/')[4] ?? 'unknown';

        // 1. No VNet integration on environment
        const vnetConfig = env.vnetConfiguration;
        const hasVnet = vnetConfig?.infrastructureSubnetId !== undefined;
        if (!hasVnet) {
          findings.push(this.finding(
            'Container Apps Environment has no Virtual Network integration',
            `Container Apps Environment "${envName}" is not deployed into a VNet. All container-to-container traffic and backend access flows over shared infrastructure without private network isolation.`,
            'HIGH',
            { environment: envName, resourceGroup: rg },
            'Deploy the Container Apps Environment with VNet integration by specifying an infrastructure subnet. Enable "internal" mode to prevent public inbound access.',
            ['containerapps', 'network', 'vnet'],
          ));
        }

        // 2. Environment with external (public) ingress allowed
        const isInternal = env.vnetConfiguration?.internal === true;
        if (hasVnet && !isInternal) {
          findings.push(this.finding(
            'Container Apps Environment is configured with external (public) access',
            `Container Apps Environment "${envName}" is deployed in external mode. Container Apps within this environment can be exposed publicly without a WAF or API Gateway in front.`,
            'MEDIUM',
            { environment: envName, resourceGroup: rg },
            'Use internal VNet mode for the environment and place Azure Front Door or API Management with WAF in front for external traffic. Only expose apps that explicitly require public access.',
            ['containerapps', 'network', 'public-access'],
          ));
        }

        // 3. No Log Analytics workspace connected
        const logAnalyticsId = env.appLogsConfiguration?.logAnalyticsConfiguration?.customerId;
        if (!logAnalyticsId) {
          findings.push(this.finding(
            'Container Apps Environment has no Log Analytics workspace configured',
            `Container Apps Environment "${envName}" has no Log Analytics workspace. Container stdout/stderr logs, system logs, and audit events will not be centrally captured.`,
            'MEDIUM',
            { environment: envName, resourceGroup: rg },
            'Configure a Log Analytics workspace on the Container Apps Environment to capture all container and system logs for monitoring and security analysis.',
            ['containerapps', 'logging'],
          ));
        }
      }

      // Scan individual Container Apps
      const apps: any[] = [];
      for await (const app of caClient.containerApps.listBySubscription()) apps.push(app);

      for (const app of apps) {
        const name = app.name ?? 'unknown';
        const rg = app.id?.split('/')[4] ?? 'unknown';
        const ingress = app.configuration?.ingress;

        // 4. Public external ingress without transport TLS
        if (ingress?.external === true) {
          if (ingress.transport === 'http') {
            findings.push(this.finding(
              'Azure Container App has external HTTP ingress without TLS',
              `Container App "${name}" accepts external (public) HTTP traffic without TLS. Data exchanged with clients is transmitted in plaintext.`,
              'HIGH',
              { app: name, resourceGroup: rg, transport: ingress.transport },
              'Set ingress.transport to "http2" or "auto" which enforces TLS termination. Ensure client-facing URLs use HTTPS.',
              ['containerapps', 'encryption-in-transit'],
            ));
          }
        }

        // 5. Allow insecure connections on ingress
        if (ingress?.allowInsecure === true) {
          findings.push(this.finding(
            'Azure Container App allows insecure HTTP connections',
            `Container App "${name}" has allowInsecure set to true. HTTP requests are served without redirect to HTTPS, exposing traffic to interception.`,
            'HIGH',
            { app: name, resourceGroup: rg },
            'Set ingress.allowInsecure to false to automatically redirect HTTP to HTTPS.',
            ['containerapps', 'tls'],
          ));
        }

        // 6. No managed identity
        const hasManagedIdentity = app.identity?.type &&
          (app.identity.type.includes('SystemAssigned') || app.identity.type.includes('UserAssigned'));
        if (!hasManagedIdentity) {
          findings.push(this.finding(
            'Azure Container App has no managed identity assigned',
            `Container App "${name}" has no managed identity. Without managed identity, secrets (database connections, API keys) must be embedded in container environment variables or configuration.`,
            'MEDIUM',
            { app: name, resourceGroup: rg },
            'Enable system-assigned managed identity on the Container App. Use it to pull images from ACR, access Key Vault secrets, and connect to Azure services without credentials.',
            ['containerapps', 'identity'],
          ));
        }

        // 7. Secrets stored as plaintext environment variables (not Key Vault references)
        const containers = app.template?.containers ?? [];
        for (const container of containers) {
          const envVars = container.env ?? [];
          const plaintextSecrets = envVars.filter((e: any) =>
            !e.secretRef &&
            (e.name?.toLowerCase().includes('key') ||
             e.name?.toLowerCase().includes('secret') ||
             e.name?.toLowerCase().includes('password') ||
             e.name?.toLowerCase().includes('token') ||
             e.name?.toLowerCase().includes('connectionstring')),
          );
          if (plaintextSecrets.length > 0) {
            findings.push(this.finding(
              'Azure Container App has potential secrets in plaintext environment variables',
              `Container App "${name}" container "${container.name}" has ${plaintextSecrets.length} environment variable(s) with names suggesting secrets that are not Key Vault references: ${plaintextSecrets.slice(0, 5).map((e: any) => e.name).join(', ')}.`,
              'HIGH',
              { app: name, resourceGroup: rg, container: container.name, count: plaintextSecrets.length },
              'Move secrets to Azure Key Vault and reference them via Container App secrets (secretRef). Never embed credentials directly in environment variable values.',
              ['containerapps', 'secrets'],
            ));
          }
        }

        // 8. Min replicas set to 0 (no HA guarantee)
        const minReplicas = app.template?.scale?.minReplicas ?? 0;
        if (minReplicas === 0) {
          findings.push(this.finding(
            'Azure Container App scales to zero — no minimum availability guarantee',
            `Container App "${name}" has minReplicas set to 0. The app can be completely scaled down, resulting in cold-start latency and potential availability gaps for steady-state workloads.`,
            'LOW',
            { app: name, resourceGroup: rg, minReplicas },
            'Set minReplicas to 1 or more for production workloads to ensure at least one instance is always running and responsive.',
            ['containerapps', 'availability'],
          ));
        }

        // 9. Privileged containers
        for (const container of containers) {
          if ((container as any).securityContext?.privileged === true) {
            findings.push(this.finding(
              'Azure Container App runs a privileged container',
              `Container App "${name}" container "${container.name}" runs in privileged mode. Privileged containers have full host access and can escape container isolation.`,
              'CRITICAL',
              { app: name, resourceGroup: rg, container: container.name },
              'Remove the privileged flag. Redesign the container workload to operate without host-level privileges. Use security contexts to drop unnecessary Linux capabilities.',
              ['containerapps', 'container-security'],
            ));
          }
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'Azure Container Apps scan error',
        `Could not complete Container Apps scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service principal has Reader permissions on Container Apps resources.',
      ));
    }

    return findings;
  }
}
