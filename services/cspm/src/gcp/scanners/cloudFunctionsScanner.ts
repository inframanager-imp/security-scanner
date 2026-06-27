import { GcpBaseScanner } from './baseScanner';
import { ScanningResult } from '../../utils/types';

export class GcpCloudFunctionsScanner extends GcpBaseScanner {
  constructor(client: import('../client').default) {
    super(client, 'GCP-CloudFunctions');
  }

  async scan(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const project = this.client.projectId;

    try {
      const cf = this.client.cloudfunctions();

      // List functions across all locations
      const res = await cf.projects.locations.functions.list({
        parent: `projects/${project}/locations/-`,
        pageSize: 500,
      });
      const functions = res.data.functions ?? [];

      if (functions.length === 0) return findings;

      for (const fn of functions) {
        const fnName   = fn.name?.split('/').pop() ?? 'unknown';
        const location = fn.name?.split('/')[3] ?? 'unknown';

        // 1. Unauthenticated (public) invocations allowed
        try {
          const iamRes = await cf.projects.locations.functions.getIamPolicy({
            resource: fn.name!,
          });
          const bindings = iamRes.data.bindings ?? [];
          const allowsAll = bindings.some(b =>
            b.role === 'roles/cloudfunctions.invoker' &&
            (b.members ?? []).some(m => m === 'allUsers' || m === 'allAuthenticatedUsers'),
          );
          if (allowsAll) {
            findings.push(this.finding(
              'Cloud Function allows unauthenticated invocations',
              `Cloud Function "${fnName}" (${location}) is publicly invocable without authentication. Any internet user can invoke this function, potentially exposing sensitive business logic or incurring unexpected costs.`,
              'HIGH',
              { function: fnName, location, project },
              'Remove "allUsers" and "allAuthenticatedUsers" from the Cloud Functions Invoker role. Use Cloud IAP or service-to-service authentication for internal callers.',
              ['cloudfunctions', 'authentication', 'public-access'],
            ));
          }
        } catch { /* IAM check optional */ }

        // 2. No VPC connector (all egress via public internet)
        const vpcConnector = fn.serviceConfig?.vpcConnector;
        if (!vpcConnector) {
          findings.push(this.finding(
            'Cloud Function has no VPC connector configured',
            `Cloud Function "${fnName}" (${location}) has no VPC connector. The function cannot reach private resources (Cloud SQL private IP, Memorystore) and all egress flows through the public internet.`,
            'MEDIUM',
            { function: fnName, location, project },
            'Configure a Serverless VPC Access connector to allow the function to reach private IP resources.',
            ['cloudfunctions', 'network', 'vpc'],
          ));
        }

        // 3. No dedicated service account (runs as default)
        const saEmail = fn.serviceConfig?.serviceAccountEmail;
        const isDefaultSA = !saEmail || saEmail.endsWith('-compute@developer.gserviceaccount.com') ||
          saEmail.includes('appspot.gserviceaccount.com');
        if (isDefaultSA) {
          findings.push(this.finding(
            'Cloud Function runs as a default service account',
            `Cloud Function "${fnName}" (${location}) runs as "${saEmail ?? 'default'}", which typically has the Editor role project-wide. This violates the principle of least privilege.`,
            'HIGH',
            { function: fnName, location, project, serviceAccount: saEmail },
            'Create a dedicated service account with only the permissions required for this function. Specify it in the serviceConfig.serviceAccountEmail field.',
            ['cloudfunctions', 'service-account', 'least-privilege'],
          ));
        }

        // 4. Plaintext secrets in environment variables
        const envVars = fn.serviceConfig?.environmentVariables ?? {};
        const suspiciousEnvVars = Object.keys(envVars).filter(k =>
          k.toLowerCase().includes('key') ||
          k.toLowerCase().includes('secret') ||
          k.toLowerCase().includes('password') ||
          k.toLowerCase().includes('token') ||
          k.toLowerCase().includes('api_key'),
        );
        if (suspiciousEnvVars.length > 0) {
          findings.push(this.finding(
            'Cloud Function may have secrets in plaintext environment variables',
            `Cloud Function "${fnName}" (${location}) has ${suspiciousEnvVars.length} environment variable(s) with names suggesting secrets: ${suspiciousEnvVars.slice(0, 5).join(', ')}. These are visible in function configuration and logs.`,
            'HIGH',
            { function: fnName, location, project, suspiciousEnvVars },
            'Use Secret Manager to store sensitive values. Reference secrets in the function configuration using secretEnvironmentVariables with Secret Manager resource names.',
            ['cloudfunctions', 'secrets'],
          ));
        }

        // 5. Minimum instances not set (cold starts, DoS risk)
        const minInstances = fn.serviceConfig?.minInstanceCount ?? 0;
        if (minInstances === 0) {
          findings.push(this.finding(
            'Cloud Function scales to zero — cold starts may impact availability',
            `Cloud Function "${fnName}" (${location}) has minInstances=0. The function scales to zero when idle, introducing cold-start latency. For security-critical functions (webhook handlers, auth callbacks), this can cause timeout-based bypasses.`,
            'LOW',
            { function: fnName, location, project },
            'Set minInstanceCount to 1 for latency-sensitive or security-critical functions.',
            ['cloudfunctions', 'availability'],
          ));
        }

        // 6. Ingress allows all traffic (not restricted to internal/load balancer)
        const ingressSettings = fn.serviceConfig?.ingressSettings;
        if (!ingressSettings || ingressSettings === 'ALLOW_ALL') {
          findings.push(this.finding(
            'Cloud Function ingress is not restricted to internal traffic',
            `Cloud Function "${fnName}" (${location}) accepts traffic from all sources (ALLOW_ALL). Functions that are only called internally or via load balancer should restrict ingress to reduce attack surface.`,
            'MEDIUM',
            { function: fnName, location, project, ingressSettings: ingressSettings ?? 'ALLOW_ALL' },
            'Set ingressSettings to ALLOW_INTERNAL_ONLY or ALLOW_INTERNAL_AND_GCLB to restrict who can invoke the function.',
            ['cloudfunctions', 'network', 'ingress'],
          ));
        }

        // 7. No build-time secret management (build environment secrets)
        const buildEnvVars = fn.buildConfig?.environmentVariables ?? {};
        const suspiciousBuildVars = Object.keys(buildEnvVars).filter(k =>
          k.toLowerCase().includes('key') ||
          k.toLowerCase().includes('secret') ||
          k.toLowerCase().includes('token'),
        );
        if (suspiciousBuildVars.length > 0) {
          findings.push(this.finding(
            'Cloud Function build configuration may contain secrets',
            `Cloud Function "${fnName}" (${location}) has ${suspiciousBuildVars.length} build environment variable(s) with names suggesting secrets: ${suspiciousBuildVars.slice(0, 5).join(', ')}. Build-time secrets are stored in plaintext in the function configuration.`,
            'MEDIUM',
            { function: fnName, location, project, suspiciousBuildVars },
            'Remove sensitive values from build environment variables. Use Cloud Build secrets or Secret Manager for build-time credentials.',
            ['cloudfunctions', 'secrets', 'cicd'],
          ));
        }
      }
    } catch (err) {
      findings.push(this.finding(
        'GCP Cloud Functions scan error',
        `Could not complete Cloud Functions scan: ${(err as Error).message}`,
        'INFO',
        { error: (err as Error).message },
        'Ensure the service account has roles/cloudfunctions.viewer on the project.',
      ));
    }

    return findings;
  }
}
