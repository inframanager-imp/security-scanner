import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class GcpCloudRunScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-CloudRun');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      const run = this.client.run();
      const res = await run.projects.locations.services.list({
        parent: `projects/${project}/locations/-`,
      });
      const services = res.data.services ?? [];

      if (services.length === 0) return findings;

      for (const svc of services) {
        const name     = svc.name?.split('/').pop() ?? 'unknown';
        const location = svc.name?.split('/')[3] ?? 'unknown';

        // 1. Unauthenticated invocations allowed
        try {
          const iamRes = await run.projects.locations.services.getIamPolicy({
            resource: svc.name!,
          });
          const bindings = iamRes.data.bindings ?? [];
          const allowsAll = bindings.some(b =>
            b.role === 'roles/run.invoker' &&
            (b.members ?? []).some(m => m === 'allUsers' || m === 'allAuthenticatedUsers'),
          );
          if (allowsAll) {
            findings.push(this.finding(
              'Cloud Run service allows unauthenticated invocations',
              `Cloud Run service "${name}" (${location}) is publicly invocable without authentication. Any internet user can invoke this service, potentially exposing sensitive business logic or data.`,
              'HIGH',
              { service: name, location, project },
              'Remove "allUsers" from the Cloud Run Invoker role. Require authentication via Cloud IAP, API Gateway, or service-to-service authentication using Workload Identity.',
              ['cloudrun', 'authentication', 'public-access'],
            ));
          }
        } catch { /* IAM check optional */ }

        // 2. No VPC connector (all egress via public internet)
        const vpcAccess = svc.template?.vpcAccess;
        if (!vpcAccess?.connector && !vpcAccess?.networkInterfaces?.length) {
          findings.push(this.finding(
            'Cloud Run service has no VPC connector configured',
            `Cloud Run service "${name}" (${location}) has no VPC connector. The service cannot reach private resources (Cloud SQL via private IP, Memorystore, internal services) and all egress traffic flows through the public internet.`,
            'MEDIUM',
            { service: name, location, project },
            'Configure a Serverless VPC Access connector to allow the Cloud Run service to reach private IP resources. Set vpcEgress to ALL_TRAFFIC to route all egress through the VPC.',
            ['cloudrun', 'network', 'vpc'],
          ));
        }

        // 3. Min instances = 0 (cold start latency)
        const minInstances = svc.template?.scaling?.minInstanceCount ?? 0;
        if (minInstances === 0) {
          findings.push(this.finding(
            'Cloud Run service scales to zero — cold starts may impact availability',
            `Cloud Run service "${name}" (${location}) has minInstances=0. The service scales to zero when idle, resulting in cold start latency on the first request after idle periods. For latency-sensitive or security-critical services, this may cause availability issues.`,
            'LOW',
            { service: name, location, project, minInstances },
            'Set minInstanceCount to 1 or more for latency-sensitive production services to eliminate cold starts.',
            ['cloudrun', 'availability'],
          ));
        }

        // 4. No service account (runs as default Compute service account)
        const saEmail = svc.template?.serviceAccount;
        if (!saEmail) {
          findings.push(this.finding(
            'Cloud Run service does not specify a service account',
            `Cloud Run service "${name}" (${location}) runs as the default Compute Engine service account, which typically has the Editor role. This violates the principle of least privilege.`,
            'HIGH',
            { service: name, location, project },
            'Create a dedicated service account with only the required roles for this Cloud Run service. Specify it in the template.serviceAccount field.',
            ['cloudrun', 'service-account', 'least-privilege'],
          ));
        }

        // 5. Secrets in environment variables (not Secret Manager)
        const containers = svc.template?.containers ?? [];
        for (const container of containers) {
          const envVars = container.env ?? [];
          const plaintextSecrets = envVars.filter(e =>
            !e.valueSource?.secretKeyRef &&
            (e.name?.toLowerCase().includes('key') ||
             e.name?.toLowerCase().includes('secret') ||
             e.name?.toLowerCase().includes('password') ||
             e.name?.toLowerCase().includes('token') ||
             e.name?.toLowerCase().includes('api_key')),
          );
          if (plaintextSecrets.length > 0) {
            findings.push(this.finding(
              'Cloud Run service may have secrets in plaintext environment variables',
              `Cloud Run service "${name}" (${location}) container has ${plaintextSecrets.length} environment variable(s) with names suggesting secrets that are not Secret Manager references: ${plaintextSecrets.slice(0, 5).map(e => e.name).join(', ')}.`,
              'HIGH',
              { service: name, location, project, suspiciousEnvVars: plaintextSecrets.map(e => e.name) },
              'Use Secret Manager to store sensitive values. Reference them in the Cloud Run service configuration using secretKeyRef instead of direct environment variable values.',
              ['cloudrun', 'secrets'],
            ));
          }
        }

        // 6. Timeout too long
        const timeout = svc.template?.timeout;
        const timeoutSecs = timeout ? parseInt(timeout.replace('s', ''), 10) : 300;
        if (timeoutSecs > 900) {
          findings.push(this.finding(
            'Cloud Run service has an excessively long request timeout',
            `Cloud Run service "${name}" (${location}) has a request timeout of ${timeoutSecs} seconds (${Math.round(timeoutSecs / 60)} minutes). Very long timeouts can increase resource consumption during DoS attacks or slow loris attacks.`,
            'LOW',
            { service: name, location, project, timeoutSeconds: timeoutSecs },
            'Set the request timeout to the minimum required for your longest-running requests. Use background jobs (Pub/Sub + Cloud Run Jobs) for long-running tasks.',
            ['cloudrun', 'availability'],
          ));
        }

        // 7. Binary Authorization not configured
        if (!svc.binaryAuthorization?.policy && svc.binaryAuthorization?.useDefault !== true) {
          findings.push(this.finding(
            'Cloud Run service does not enforce Binary Authorization',
            `Cloud Run service "${name}" (${location}) has no Binary Authorization policy. Any container image can be deployed without attestation verification.`,
            'MEDIUM',
            { service: name, location, project },
            'Enable Binary Authorization on the Cloud Run service to require that deployed images have been signed by trusted authorities.',
            ['cloudrun', 'binary-authorization', 'supply-chain'],
          ));
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'GCP Cloud Run scan error',
        `Could not complete Cloud Run scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service account has roles/run.viewer on the project.',
      ));
    }

    return findings;
  }
}
