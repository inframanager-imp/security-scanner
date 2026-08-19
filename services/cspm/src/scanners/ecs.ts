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
      findings.push(this.emit(
        'ecs_task_definition_host_network_mode',
        { resourceId: taskDef.taskDefinitionArn ?? arn, family, networkMode },
        {
          message: `ECS task definition "${family}" uses "host" network mode. ` +
            `Containers share the host's network namespace, bypassing VPC isolation and allowing access to all host network interfaces.`,
        }
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
      findings.push(this.emit(
        'ecs_task_definitions_no_privileged_containers',
        { resourceId: `${taskDefArn}::${cName}::privileged`, family, containerName: cName, taskDefArn },
        {
          message: `Container "${cName}" in task definition "${family}" runs with privileged=true. ` +
            `Privileged containers have full access to the host kernel and all devices — equivalent to root on the host.`,
        }
      ));
    }

    // 3. Running as root user (user: "0" or user: "root")
    const user = (c.user ?? '').toString();
    if (user === '0' || user.startsWith('0:') || user.toLowerCase() === 'root') {
      findings.push(this.emit(
        'ecs_container_non_root_user',
        { resourceId: `${taskDefArn}::${cName}::root-user`, family, containerName: cName, user },
        {
          message: `Container "${cName}" in task definition "${family}" runs as root user (user: "${user}"). ` +
            `If the container is compromised, the attacker has root privileges inside the container.`,
        }
      ));
    }

    // 4. Secrets in plaintext environment variables
    const secretEnvVars = (c.environment ?? []).filter(e => isSecretEnvVar(e.name ?? ''));
    if (secretEnvVars.length > 0) {
      findings.push(this.emit(
        'ecs_task_definitions_no_environment_secrets',
        {
          resourceId:    `${taskDefArn}::${cName}::env-secrets`,
          family,
          containerName: cName,
          secretEnvVars: secretEnvVars.map(e => e.name),
          taskDefArn,
        },
        {
          message: `Container "${cName}" in task definition "${family}" has ${secretEnvVars.length} environment variable(s) ` +
            `with secret-like names passed as plaintext: ${secretEnvVars.map(e => e.name).join(', ')}. ` +
            `Plaintext env vars are visible in task metadata, logs, and to anyone with DescribeTaskDefinition permission.`,
        }
      ));
    }

    // 5. No read-only root filesystem
    if (c.readonlyRootFilesystem === false || c.readonlyRootFilesystem === undefined) {
      findings.push(this.emit(
        'ecs_task_definitions_containers_readonly_access',
        { resourceId: `${taskDefArn}::${cName}::writable-fs`, family, containerName: cName },
        {
          message: `Container "${cName}" in task definition "${family}" does not have readonlyRootFilesystem enabled. ` +
            `A writable root filesystem allows attackers to modify container files and install persistence tools.`,
        }
      ));
    }

    // 6. No resource limits (CPU/memory — enables denial of service)
    if (!c.cpu && !c.memory && !c.memoryReservation) {
      findings.push(this.emit(
        'ecs_container_resource_limits_configured',
        { resourceId: `${taskDefArn}::${cName}::no-limits`, family, containerName: cName },
        {
          message: `Container "${cName}" in task definition "${family}" has no CPU or memory limits configured. ` +
            `Without limits, a compromised or buggy container can consume all host resources (noisy neighbor / DoS).`,
        }
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
              findings.push(this.emit(
                'ecs_service_deployment_circuit_breaker_enabled',
                {
                  resourceId:  `${svc.serviceArn}::circuit-breaker`,
                  serviceName: svcName,
                  clusterName,
                  serviceArn:  svc.serviceArn,
                },
                {
                  message: `ECS service "${svcName}" in cluster "${clusterName}" has no deployment circuit breaker. ` +
                    `Failed deployments will keep retrying indefinitely instead of rolling back automatically.`,
                }
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
