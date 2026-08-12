// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  ListClustersCommand,
  DescribeClustersCommand,
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

// Latest Fargate platform versions (mirrors Prowler's fargate_*_latest_version defaults)
const LATEST_FARGATE_LINUX_VERSION   = '1.4.0';
const LATEST_FARGATE_WINDOWS_VERSION = '1.0.0';

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
    const taskDefArn  = taskDef.taskDefinitionArn ?? arn;
    const revision    = taskDef.revision != null ? String(taskDef.revision) : (arn.split(':').pop() ?? '');
    const familyRev   = `${family}:${revision}`;

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

    // 2. Host PID namespace shared with containers
    if (taskDef.pidMode === 'host') {
      findings.push(this.emit(
        'ecs_task_definitions_host_namespace_not_shared',
        { resourceId: `${taskDefArn}::pid-mode`, family, revision, pidMode: 'host' },
        {
          message: `ECS task definition "${familyRev}" shares the host's process namespace with its containers (pidMode: host). ` +
            `Containers can enumerate, signal, and ptrace host processes, breaking container isolation.`,
        }
      ));
    }

    // 3. Host network mode with non-privileged containers running as root
    if (networkMode === 'host') {
      const rootContainers = containers
        .filter(c => !c.privileged && ((c.user ?? '') === '' || c.user === 'root'))
        .map(c => c.name ?? 'unknown');
      if (rootContainers.length > 0) {
        findings.push(this.emit(
          'ecs_task_definitions_host_networking_mode_users',
          { resourceId: `${taskDefArn}::host-mode-users`, family, revision, containers: rootContainers },
          {
            message: `ECS task definition "${familyRev}" uses host network mode with non-privileged container(s) running as root or with no user set: ` +
              `${rootContainers.join(', ')}. Root containers on the host network can bind low ports, sniff traffic, and impersonate host services.`,
          }
        ));
      }
    }

    // 4. Container logging: missing log driver / blocking log mode
    const unloggedContainers: string[] = [];
    const blockingContainers: string[] = [];
    for (const c of containers) {
      const logConfig: any = c.logConfiguration;
      if (!logConfig?.logDriver) {
        unloggedContainers.push(c.name ?? 'unknown');
      } else if ((logConfig.options?.mode ?? '') !== 'non-blocking') {
        blockingContainers.push(c.name ?? 'unknown');
      }
    }
    if (unloggedContainers.length > 0) {
      findings.push(this.emit(
        'ecs_task_definitions_logging_enabled',
        { resourceId: `${taskDefArn}::no-logging`, family, revision, containers: unloggedContainers },
        {
          message: `ECS task definition "${familyRev}" has container(s) with no logging configuration: ${unloggedContainers.join(', ')}. ` +
            `Without container logs, intrusions and tampering go undetected and forensics is impossible.`,
        }
      ));
    }
    if (blockingContainers.length > 0) {
      findings.push(this.emit(
        'ecs_task_definitions_logging_block_mode',
        { resourceId: `${taskDefArn}::blocking-log-mode`, family, revision, containers: blockingContainers },
        {
          message: `ECS task definition "${familyRev}" has container(s) logging in blocking mode: ${blockingContainers.join(', ')}. ` +
            `If the log destination stalls, writes to stdout/stderr block and the container becomes unresponsive.`,
          remediation: `Set "mode": "non-blocking" (with an appropriate max-buffer-size) in the logConfiguration options of containers ${blockingContainers.join(', ')} in task definition "${family}".`,
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

    const clusters = clusterArns.slice(0, 10);

    // ecs_cluster_container_insights_enabled (cluster-level settings)
    findings.push(...(await this.scanClusterSettings(clusters)));

    for (const clusterArn of clusters) {
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

            // ecs_service_no_assign_public_ip: tasks must not get public IPs automatically
            const assignPublicIp = svc.networkConfiguration?.awsvpcConfiguration?.assignPublicIp ?? 'DISABLED';
            if (assignPublicIp === 'ENABLED') {
              findings.push(this.emit(
                'ecs_service_no_assign_public_ip',
                {
                  resourceId:  `${svc.serviceArn}::public-ip`,
                  serviceName: svcName,
                  clusterName,
                  serviceArn:  svc.serviceArn,
                },
                {
                  message: `ECS service "${svcName}" in cluster "${clusterName}" automatically assigns public IPs to its tasks, ` +
                    `making them directly reachable from the internet for scanning, brute force, and exploitation.`,
                  remediation: `Disable public IP assignment: aws ecs update-service --cluster ${clusterName} --service ${svcName} --network-configuration "awsvpcConfiguration={subnets=[...],assignPublicIp=DISABLED}" and expose the service through a load balancer instead.`,
                }
              ));
            }

            // ecs_service_fargate_latest_platform_version
            if (svc.launchType === 'FARGATE') {
              // platformFamily is e.g. "LINUX" or "WINDOWS_SERVER_2019_CORE"
              const platformFamily  = svc.platformFamily ?? 'LINUX';
              const latestVersion   = platformFamily.toUpperCase().includes('WINDOWS')
                ? LATEST_FARGATE_WINDOWS_VERSION
                : LATEST_FARGATE_LINUX_VERSION;
              const platformVersion = svc.platformVersion ?? '';
              if (platformVersion !== 'LATEST' && platformVersion !== latestVersion) {
                findings.push(this.emit(
                  'ecs_service_fargate_latest_platform_version',
                  {
                    resourceId:  `${svc.serviceArn}::platform-version`,
                    serviceName: svcName,
                    clusterName,
                    platformFamily,
                    platformVersion,
                  },
                  {
                    message: `ECS Fargate service "${svcName}" in cluster "${clusterName}" uses ${platformFamily} platform version ` +
                      `${platformVersion || 'unknown'} instead of the latest (${latestVersion}). Outdated platform versions miss kernel and runtime security patches.`,
                    remediation: `Update the service to the latest platform version: aws ecs update-service --cluster ${clusterName} --service ${svcName} --platform-version LATEST`,
                  }
                ));
              }
            }

            // ecs_task_set_no_assign_public_ip: task sets must not get public IPs automatically
            for (const taskSet of svc.taskSets ?? []) {
              const tsAssignPublicIp = taskSet.networkConfiguration?.awsvpcConfiguration?.assignPublicIp ?? 'DISABLED';
              if (tsAssignPublicIp === 'ENABLED') {
                findings.push(this.emit(
                  'ecs_task_set_no_assign_public_ip',
                  {
                    resourceId:  `${taskSet.taskSetArn}::public-ip`,
                    taskSetId:   taskSet.id,
                    serviceName: svcName,
                    clusterName,
                  },
                  {
                    message: `ECS task set "${taskSet.id}" of service "${svcName}" in cluster "${clusterName}" automatically assigns ` +
                      `public IPs to its tasks, making them directly reachable from the internet.`,
                  }
                ));
              }
            }
          }
        }
      } catch { /* no permission for this cluster */ }
    }

    return findings;
  }

  /** ecs_cluster_container_insights_enabled — Container Insights must be enabled or enhanced. */
  private async scanClusterSettings(clusterArns: string[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    if (clusterArns.length === 0) return findings;

    try {
      const result = await retry(() =>
        this.client.ecs.send(new DescribeClustersCommand({ clusters: clusterArns, include: ['SETTINGS'] }))
      );
      for (const cluster of result.clusters ?? []) {
        const clusterName = cluster.clusterName ?? cluster.clusterArn ?? 'Unknown';
        const insights = (cluster.settings ?? []).find(s => s.name === 'containerInsights')?.value ?? 'disabled';
        if (insights !== 'enabled' && insights !== 'enhanced') {
          findings.push(this.emit(
            'ecs_cluster_container_insights_enabled',
            { resourceId: `${cluster.clusterArn}::container-insights`, clusterName, containerInsights: insights },
            {
              message: `ECS cluster "${clusterName}" does not have Container Insights enabled. ` +
                `Without cluster, service, and task telemetry, failures, restart loops, and abuse (e.g. cryptomining) go undetected.`,
              remediation: `Enable Container Insights: aws ecs update-cluster-settings --cluster ${clusterName} --settings name=containerInsights,value=enabled`,
            }
          ));
        }
      }
    } catch (err) {
      logger.debug('ECS: failed to describe cluster settings', { error: (err as Error).message });
    }

    return findings;
  }
}

export default ECSScanner;
