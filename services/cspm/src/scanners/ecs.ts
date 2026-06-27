import {
  ListClustersCommand,
  ListTaskDefinitionsCommand,
  DescribeTaskDefinitionCommand,
  ListServicesCommand,
  DescribeServicesCommand,
  type TaskDefinition,
  type ContainerDefinition,
} from '@aws-sdk/client-ecs';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Secrets patterns in env var names
const SECRET_ENV_PATTERNS = [
  /password/i, /passwd/i, /secret/i, /api[_-]?key/i, /token/i,
  /credential/i, /private[_-]?key/i, /access[_-]?key/i, /auth/i, /db[_-]?pass/i,
];

function isSecretEnvVar(name: string): boolean {
  return SECRET_ENV_PATTERNS.some(p => p.test(name));
}

export class ECSScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'ECS');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting ECS security scan...');

    // Scan active task definitions (latest revision per family)
    const taskDefArns = await this.listActiveTaskDefinitions();
    logger.info(`ECS: scanning ${taskDefArns.length} active task definition(s)`);

    for (const arn of taskDefArns) {
      findings.push(...(await this.scanTaskDefinition(arn)));
    }

    // Scan services for misconfiguration
    findings.push(...(await this.scanServices()));

    logger.info(`ECS scan complete. ${findings.length} findings.`);
    return findings;
  }

  private async listActiveTaskDefinitions(): Promise<string[]> {
    const arns: string[] = [];
    let nextToken: string | undefined;
    try {
      do {
        const result = await retry(() =>
          this.client.ecs.send(new ListTaskDefinitionsCommand({
            status: 'ACTIVE',
            sort: 'DESC',
            nextToken,
            maxResults: 100,
          }))
        );
        // Only keep the latest revision per family (DESC sort + dedup by family name)
        const seen = new Set<string>();
        for (const arn of result.taskDefinitionArns ?? []) {
          const family = arn.split('/').pop()?.replace(/:\d+$/, '') ?? arn;
          if (!seen.has(family)) {
            seen.add(family);
            arns.push(arn);
          }
        }
        nextToken = result.nextToken;
      } while (nextToken && arns.length < 200);
    } catch { /* no permission */ }
    return arns;
  }

  private async scanTaskDefinition(arn: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    let taskDef: TaskDefinition | undefined;
    try {
      const result = await retry(() =>
        this.client.ecs.send(new DescribeTaskDefinitionCommand({ taskDefinition: arn }))
      );
      taskDef = result.taskDefinition;
    } catch { return findings; }

    if (!taskDef) return findings;

    const family      = taskDef.family         ?? arn.split('/').pop() ?? arn;
    const networkMode = taskDef.networkMode     ?? 'bridge';
    const containers  = taskDef.containerDefinitions ?? [];

    // 1. Host network mode (bypasses VPC isolation)
    if (networkMode === 'host') {
      findings.push(this.createFinding(
        'ECS Task Definition Uses Host Network Mode',
        `ECS task definition "${family}" uses "host" network mode. ` +
        `Containers share the host's network namespace, bypassing VPC isolation and allowing access to all host network interfaces.`,
        'HIGH',
        { resourceId: taskDef.taskDefinitionArn ?? arn, family, networkMode },
        `Change network mode to "awsvpc" for better isolation. Each task gets its own ENI and security group.`,
        ['ecs', 'network', 'isolation'],
      ));
    }

    for (const container of containers) {
      findings.push(...this.scanContainer(family, taskDef.taskDefinitionArn ?? arn, container));
    }

    return findings;
  }

  private scanContainer(family: string, taskDefArn: string, c: ContainerDefinition): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const cName = c.name ?? 'unknown';

    // 2. Privileged container
    if (c.privileged) {
      findings.push(this.createFinding(
        'ECS Container Running in Privileged Mode',
        `Container "${cName}" in task definition "${family}" runs with privileged=true. ` +
        `Privileged containers have full access to the host kernel and all devices — equivalent to root on the host.`,
        'CRITICAL',
        { resourceId: `${taskDefArn}::${cName}::privileged`, family, containerName: cName, taskDefArn },
        `Remove "privileged: true" from the container definition. Use specific Linux capabilities instead if needed.`,
        ['ecs', 'container', 'privilege'],
      ));
    }

    // 3. Running as root user (user: "0" or user: "root")
    const user = (c.user ?? '').toString();
    if (user === '0' || user.startsWith('0:') || user.toLowerCase() === 'root') {
      findings.push(this.createFinding(
        'ECS Container Running as Root User',
        `Container "${cName}" in task definition "${family}" runs as root user (user: "${user}"). ` +
        `If the container is compromised, the attacker has root privileges inside the container.`,
        'HIGH',
        { resourceId: `${taskDefArn}::${cName}::root-user`, family, containerName: cName, user },
        `Set a non-root user in the Dockerfile (USER 1000) or in the task definition user field.`,
        ['ecs', 'container', 'privilege'],
      ));
    }

    // 4. Secrets in plaintext environment variables
    const secretEnvVars = (c.environment ?? []).filter(e => isSecretEnvVar(e.name ?? ''));
    if (secretEnvVars.length > 0) {
      findings.push(this.createFinding(
        'ECS Container Has Secrets in Plaintext Environment Variables',
        `Container "${cName}" in task definition "${family}" has ${secretEnvVars.length} environment variable(s) ` +
        `with secret-like names passed as plaintext: ${secretEnvVars.map(e => e.name).join(', ')}. ` +
        `Plaintext env vars are visible in task metadata, logs, and to anyone with DescribeTaskDefinition permission.`,
        'HIGH',
        {
          resourceId:    `${taskDefArn}::${cName}::env-secrets`,
          family,
          containerName: cName,
          secretEnvVars: secretEnvVars.map(e => e.name),
          taskDefArn,
        },
        `Replace plaintext env vars with ECS secrets integration: use "secrets" field referencing ` +
        `SSM Parameter Store SecureString or Secrets Manager ARNs. ` +
        `Example: { "name": "DB_PASSWORD", "valueFrom": "arn:aws:ssm:region:account:parameter/db-password" }`,
        ['ecs', 'container', 'secrets'],
      ));
    }

    // 5. No read-only root filesystem
    if (c.readonlyRootFilesystem === false || c.readonlyRootFilesystem === undefined) {
      findings.push(this.createFinding(
        'ECS Container Root Filesystem Not Read-Only',
        `Container "${cName}" in task definition "${family}" does not have readonlyRootFilesystem enabled. ` +
        `A writable root filesystem allows attackers to modify container files and install persistence tools.`,
        'MEDIUM',
        { resourceId: `${taskDefArn}::${cName}::writable-fs`, family, containerName: cName },
        `Enable read-only root filesystem in the container definition: "readonlyRootFilesystem": true. ` +
        `Mount writable volumes only for directories that genuinely need write access (e.g. /tmp).`,
        ['ecs', 'container', 'filesystem'],
      ));
    }

    // 6. No resource limits (CPU/memory — enables denial of service)
    if (!c.cpu && !c.memory && !c.memoryReservation) {
      findings.push(this.createFinding(
        'ECS Container Has No Resource Limits',
        `Container "${cName}" in task definition "${family}" has no CPU or memory limits configured. ` +
        `Without limits, a compromised or buggy container can consume all host resources (noisy neighbor / DoS).`,
        'LOW',
        { resourceId: `${taskDefArn}::${cName}::no-limits`, family, containerName: cName },
        `Set CPU and memory limits on the container definition to prevent resource exhaustion.`,
        ['ecs', 'container', 'resources'],
      ));
    }

    return findings;
  }

  private async scanServices(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    // List clusters then services — check for services without load balancer health checks
    let clusterArns: string[] = [];
    try {
      const result = await retry(() =>
        this.client.ecs.send(new ListClustersCommand({ maxResults: 100 }))
      );
      clusterArns = result.clusterArns ?? [];
    } catch { return findings; }

    for (const clusterArn of clusterArns.slice(0, 10)) {
      try {
        let nextToken: string | undefined;
        const serviceArns: string[] = [];
        do {
          const result = await retry(() =>
            this.client.ecs.send(new ListServicesCommand({ cluster: clusterArn, nextToken, maxResults: 100 }))
          );
          serviceArns.push(...(result.serviceArns ?? []));
          nextToken = result.nextToken;
        } while (nextToken && serviceArns.length < 100);

        if (serviceArns.length === 0) continue;

        // Describe in batches of 10 (API limit)
        for (let i = 0; i < serviceArns.length; i += 10) {
          const batch = serviceArns.slice(i, i + 10);
          const result = await retry(() =>
            this.client.ecs.send(new DescribeServicesCommand({ cluster: clusterArn, services: batch }))
          );

          for (const svc of result.services ?? []) {
            const svcName = svc.serviceName ?? 'Unknown';
            const clusterName = clusterArn.split('/').pop() ?? clusterArn;

            // Service with no deployment circuit breaker (silent failures)
            const deployConfig = svc.deploymentConfiguration;
            if (!deployConfig?.deploymentCircuitBreaker?.enable) {
              findings.push(this.createFinding(
                'ECS Service Deployment Circuit Breaker Disabled',
                `ECS service "${svcName}" in cluster "${clusterName}" has no deployment circuit breaker. ` +
                `Failed deployments will keep retrying indefinitely instead of rolling back automatically.`,
                'LOW',
                {
                  resourceId:  `${svc.serviceArn}::circuit-breaker`,
                  serviceName: svcName,
                  clusterName,
                  serviceArn:  svc.serviceArn,
                },
                `Enable deployment circuit breaker with rollback: set deploymentCircuitBreaker.enable=true and rollback=true in service configuration.`,
                ['ecs', 'service', 'deployment'],
              ));
            }
          }
        }
      } catch { /* no permission for this cluster */ }
    }

    return findings;
  }
}

export default ECSScanner;
