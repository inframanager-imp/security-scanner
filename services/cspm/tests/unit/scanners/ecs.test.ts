import { describe, it, expect, beforeEach } from '@jest/globals';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import {
  ECSClient,
  ListClustersCommand,
  DescribeClustersCommand,
  ListTaskDefinitionsCommand,
  DescribeTaskDefinitionCommand,
  ListServicesCommand,
  DescribeServicesCommand,
} from '@aws-sdk/client-ecs';
import ECSScanner from '../../../src/scanners/ecs';

// The scanner reaches AWS exclusively through `client.ecs` (a pre-built ECSClient
// on the AWSClient wrapper), so the mock AWSClient only needs that one property.
const ecsMock = mockClient(ECSClient);

function makeClient(): any {
  return {
    ecs: new ECSClient({ region: 'us-east-1', credentials: { accessKeyId: 'x', secretAccessKey: 'y' } }),
    getClientConfig: () => ({ region: 'us-east-1', credentials: { accessKeyId: 'x', secretAccessKey: 'y' } }),
  };
}

// A "clean" task definition that should not trip any of the per-container checks
// (host network mode is not "host", not privileged, non-root user, read-only fs,
// resource limits set, logging configured non-blocking).
function cleanContainer(name = 'app') {
  return {
    name,
    privileged: false,
    user: '1000',
    readonlyRootFilesystem: true,
    cpu: 256,
    memory: 512,
    environment: [{ name: 'APP_ENV', value: 'production' }],
    logConfiguration: {
      logDriver: 'awslogs',
      options: { mode: 'non-blocking' },
    },
  };
}

function cleanTaskDefinition(family: string, revision = 1, overrides: any = {}) {
  return {
    family,
    revision,
    networkMode: 'awsvpc',
    taskDefinitionArn: `arn:aws:ecs:us-east-1:123456789012:task-definition/${family}:${revision}`,
    containerDefinitions: [cleanContainer()],
    ...overrides,
  };
}

describe('ECSScanner', () => {
  beforeEach(() => {
    ecsMock.reset();
    // Defaults so scanServices()'s cluster-listing path resolves to "no clusters"
    // unless a test explicitly sets up clusters/services.
    ecsMock.on(ListClustersCommand).resolves({ clusterArns: [] });
    ecsMock.on(ListTaskDefinitionsCommand).resolves({ taskDefinitionArns: [] });
  });

  describe('scan() - task definitions', () => {
    it('returns no findings when there are no active task definitions and no clusters', async () => {
      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });

    it('flags a task definition using host network mode, and does not flag a clean awsvpc one', async () => {
      ecsMock.on(ListTaskDefinitionsCommand).resolves({
        taskDefinitionArns: [
          'arn:aws:ecs:us-east-1:123456789012:task-definition/host-task:1',
        ],
      });
      ecsMock.on(DescribeTaskDefinitionCommand).resolves({
        taskDefinition: cleanTaskDefinition('host-task', 1, { networkMode: 'host' }),
      });

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      const hostNetworkFindings = findings.filter(f => f.checkId === 'ecs_task_definition_host_network_mode');
      expect(hostNetworkFindings).toHaveLength(1);
      expect(hostNetworkFindings[0]).toMatchObject({
        checkId: 'ecs_task_definition_host_network_mode',
        service: 'ECS',
        severity: expect.any(String),
      });
      expect(hostNetworkFindings[0].evidence).toMatchObject({
        family: 'host-task',
        networkMode: 'host',
      });
    });

    it('does not flag a task definition using awsvpc network mode with a clean container', async () => {
      ecsMock.on(ListTaskDefinitionsCommand).resolves({
        taskDefinitionArns: [
          'arn:aws:ecs:us-east-1:123456789012:task-definition/clean-task:1',
        ],
      });
      ecsMock.on(DescribeTaskDefinitionCommand).resolves({
        taskDefinition: cleanTaskDefinition('clean-task'),
      });

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.checkId === 'ecs_task_definition_host_network_mode')).toBe(false);
      expect(findings.some(f => f.checkId === 'ecs_task_definitions_no_privileged_containers')).toBe(false);
      expect(findings.some(f => f.checkId === 'ecs_container_non_root_user')).toBe(false);
      expect(findings.some(f => f.checkId === 'ecs_task_definitions_containers_readonly_access')).toBe(false);
      expect(findings.some(f => f.checkId === 'ecs_container_resource_limits_configured')).toBe(false);
    });

    it('flags a privileged container running as root with plaintext secrets and no read-only fs or resource limits', async () => {
      ecsMock.on(ListTaskDefinitionsCommand).resolves({
        taskDefinitionArns: [
          'arn:aws:ecs:us-east-1:123456789012:task-definition/risky-task:1',
        ],
      });
      ecsMock.on(DescribeTaskDefinitionCommand).resolves({
        taskDefinition: {
          family: 'risky-task',
          revision: 1,
          networkMode: 'awsvpc',
          taskDefinitionArn: 'arn:aws:ecs:us-east-1:123456789012:task-definition/risky-task:1',
          containerDefinitions: [
            {
              name: 'bad-container',
              privileged: true,
              user: 'root',
              readonlyRootFilesystem: false,
              environment: [
                { name: 'DB_PASSWORD', value: 'hunter2' },
                { name: 'APP_ENV', value: 'production' },
              ],
              logConfiguration: { logDriver: 'awslogs', options: { mode: 'non-blocking' } },
            },
          ],
        },
      });

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      const byCheckId = (id: string) => findings.find(f => f.checkId === id);

      expect(byCheckId('ecs_task_definitions_no_privileged_containers')).toBeDefined();
      expect(byCheckId('ecs_task_definitions_no_privileged_containers')?.evidence).toMatchObject({
        family: 'risky-task',
        containerName: 'bad-container',
      });

      expect(byCheckId('ecs_container_non_root_user')).toBeDefined();
      expect(byCheckId('ecs_container_non_root_user')?.evidence).toMatchObject({ user: 'root' });

      const secretsFinding = byCheckId('ecs_task_definitions_no_environment_secrets');
      expect(secretsFinding).toBeDefined();
      expect(secretsFinding?.evidence).toMatchObject({
        containerName: 'bad-container',
        secretEnvVars: ['DB_PASSWORD'],
      });

      expect(byCheckId('ecs_task_definitions_containers_readonly_access')).toBeDefined();
      expect(byCheckId('ecs_container_resource_limits_configured')).toBeDefined();
    });

    it('flags shared host PID namespace and host-network containers running as root', async () => {
      ecsMock.on(ListTaskDefinitionsCommand).resolves({
        taskDefinitionArns: [
          'arn:aws:ecs:us-east-1:123456789012:task-definition/host-pid-task:2',
        ],
      });
      ecsMock.on(DescribeTaskDefinitionCommand).resolves({
        taskDefinition: {
          family: 'host-pid-task',
          revision: 2,
          networkMode: 'host',
          pidMode: 'host',
          taskDefinitionArn: 'arn:aws:ecs:us-east-1:123456789012:task-definition/host-pid-task:2',
          containerDefinitions: [
            {
              name: 'unprivileged-root',
              privileged: false,
              user: '',
              readonlyRootFilesystem: true,
              cpu: 128,
              logConfiguration: { logDriver: 'awslogs', options: { mode: 'non-blocking' } },
            },
          ],
        },
      });

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      const pidFinding = findings.find(f => f.checkId === 'ecs_task_definitions_host_namespace_not_shared');
      expect(pidFinding).toBeDefined();
      expect(pidFinding?.evidence).toMatchObject({ family: 'host-pid-task', pidMode: 'host' });

      const hostModeUsersFinding = findings.find(f => f.checkId === 'ecs_task_definitions_host_networking_mode_users');
      expect(hostModeUsersFinding).toBeDefined();
      expect(hostModeUsersFinding?.evidence).toMatchObject({
        family: 'host-pid-task',
        containers: ['unprivileged-root'],
      });
    });

    it('flags containers with no logging configuration and containers logging in blocking mode', async () => {
      ecsMock.on(ListTaskDefinitionsCommand).resolves({
        taskDefinitionArns: [
          'arn:aws:ecs:us-east-1:123456789012:task-definition/log-task:1',
        ],
      });
      ecsMock.on(DescribeTaskDefinitionCommand).resolves({
        taskDefinition: {
          family: 'log-task',
          revision: 1,
          networkMode: 'awsvpc',
          taskDefinitionArn: 'arn:aws:ecs:us-east-1:123456789012:task-definition/log-task:1',
          containerDefinitions: [
            {
              name: 'no-log-container',
              privileged: false,
              user: '1000',
              readonlyRootFilesystem: true,
              cpu: 128,
              // no logConfiguration at all
            },
            {
              name: 'blocking-log-container',
              privileged: false,
              user: '1000',
              readonlyRootFilesystem: true,
              cpu: 128,
              logConfiguration: { logDriver: 'awslogs', options: { mode: 'blocking' } },
            },
          ],
        },
      });

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      const noLoggingFinding = findings.find(f => f.checkId === 'ecs_task_definitions_logging_enabled');
      expect(noLoggingFinding).toBeDefined();
      expect(noLoggingFinding?.evidence).toMatchObject({
        family: 'log-task',
        containers: ['no-log-container'],
      });

      const blockingModeFinding = findings.find(f => f.checkId === 'ecs_task_definitions_logging_block_mode');
      expect(blockingModeFinding).toBeDefined();
      expect(blockingModeFinding?.evidence).toMatchObject({
        family: 'log-task',
        containers: ['blocking-log-container'],
      });
    });

    it('paginates through ListTaskDefinitionsCommand using nextToken, keeping only the latest revision per family', async () => {
      ecsMock
        .on(ListTaskDefinitionsCommand)
        .resolvesOnce({
          taskDefinitionArns: [
            'arn:aws:ecs:us-east-1:123456789012:task-definition/family-a:3',
          ],
          nextToken: 'token-2',
        })
        .resolvesOnce({
          taskDefinitionArns: [
            'arn:aws:ecs:us-east-1:123456789012:task-definition/family-b:1',
          ],
        });
      ecsMock.on(DescribeTaskDefinitionCommand).callsFake((input: any) => {
        const arn: string = input.taskDefinition;
        const family = arn.split('/').pop()!.split(':')[0];
        const revision = Number(arn.split(':').pop());
        return Promise.resolve({
          taskDefinition: cleanTaskDefinition(family, revision, { networkMode: 'host' }),
        });
      });

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      expect(ecsMock.commandCalls(ListTaskDefinitionsCommand)).toHaveLength(2);
      const flaggedFamilies = findings
        .filter(f => f.checkId === 'ecs_task_definition_host_network_mode')
        .map(f => f.evidence.family)
        .sort();
      expect(flaggedFamilies).toEqual(['family-a', 'family-b']);
    });

    it('does not throw and returns gracefully when ListTaskDefinitionsCommand fails (no permission)', async () => {
      ecsMock.on(ListTaskDefinitionsCommand).rejects(new Error('Access Denied'));

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    });

    it('does not throw and skips the task definition when DescribeTaskDefinitionCommand fails repeatedly', async () => {
      ecsMock.on(ListTaskDefinitionsCommand).resolves({
        taskDefinitionArns: [
          'arn:aws:ecs:us-east-1:123456789012:task-definition/broken-task:1',
        ],
      });
      ecsMock.on(DescribeTaskDefinitionCommand).rejects(new Error('Access Denied'));

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    }, 15000);
  });

  describe('scan() - services and clusters', () => {
    it('returns no service findings when the account has no clusters', async () => {
      ecsMock.on(ListClustersCommand).resolves({ clusterArns: [] });

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.service === 'ECS' && f.checkId?.startsWith('ecs_service'))).toBe(false);
      expect(findings.some(f => f.checkId === 'ecs_cluster_container_insights_enabled')).toBe(false);
    });

    it('flags a cluster with Container Insights disabled', async () => {
      ecsMock.on(ListClustersCommand).resolves({
        clusterArns: ['arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster'],
      });
      ecsMock.on(DescribeClustersCommand).resolves({
        clusters: [
          {
            clusterArn: 'arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster',
            clusterName: 'my-cluster',
            settings: [{ name: 'containerInsights', value: 'disabled' }],
          },
        ],
      });
      ecsMock.on(ListServicesCommand).resolves({ serviceArns: [] });

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      const insightsFinding = findings.find(f => f.checkId === 'ecs_cluster_container_insights_enabled');
      expect(insightsFinding).toBeDefined();
      expect(insightsFinding?.evidence).toMatchObject({
        clusterName: 'my-cluster',
        containerInsights: 'disabled',
      });
    });

    it('does not flag a cluster with Container Insights enhanced', async () => {
      ecsMock.on(ListClustersCommand).resolves({
        clusterArns: ['arn:aws:ecs:us-east-1:123456789012:cluster/good-cluster'],
      });
      ecsMock.on(DescribeClustersCommand).resolves({
        clusters: [
          {
            clusterArn: 'arn:aws:ecs:us-east-1:123456789012:cluster/good-cluster',
            clusterName: 'good-cluster',
            settings: [{ name: 'containerInsights', value: 'enhanced' }],
          },
        ],
      });
      ecsMock.on(ListServicesCommand).resolves({ serviceArns: [] });

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.checkId === 'ecs_cluster_container_insights_enabled')).toBe(false);
    });

    it('flags a service with no deployment circuit breaker and public IP auto-assignment', async () => {
      ecsMock.on(ListClustersCommand).resolves({
        clusterArns: ['arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster'],
      });
      ecsMock.on(DescribeClustersCommand).resolves({
        clusters: [
          {
            clusterArn: 'arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster',
            clusterName: 'my-cluster',
            settings: [{ name: 'containerInsights', value: 'enabled' }],
          },
        ],
      });
      ecsMock.on(ListServicesCommand).resolves({
        serviceArns: ['arn:aws:ecs:us-east-1:123456789012:service/my-cluster/my-service'],
      });
      ecsMock.on(DescribeServicesCommand).resolves({
        services: [
          {
            serviceArn: 'arn:aws:ecs:us-east-1:123456789012:service/my-cluster/my-service',
            serviceName: 'my-service',
            deploymentConfiguration: {},
            networkConfiguration: {
              awsvpcConfiguration: { assignPublicIp: 'ENABLED' },
            },
          },
        ],
      });

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      const circuitBreakerFinding = findings.find(f => f.checkId === 'ecs_service_deployment_circuit_breaker_enabled');
      expect(circuitBreakerFinding).toBeDefined();
      expect(circuitBreakerFinding?.evidence).toMatchObject({
        serviceName: 'my-service',
        clusterName: 'my-cluster',
      });

      const publicIpFinding = findings.find(f => f.checkId === 'ecs_service_no_assign_public_ip');
      expect(publicIpFinding).toBeDefined();
      expect(publicIpFinding?.evidence).toMatchObject({
        serviceName: 'my-service',
        clusterName: 'my-cluster',
      });
    });

    it('does not flag a service with circuit breaker enabled and public IP disabled', async () => {
      ecsMock.on(ListClustersCommand).resolves({
        clusterArns: ['arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster'],
      });
      ecsMock.on(DescribeClustersCommand).resolves({
        clusters: [
          {
            clusterArn: 'arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster',
            clusterName: 'my-cluster',
            settings: [{ name: 'containerInsights', value: 'enabled' }],
          },
        ],
      });
      ecsMock.on(ListServicesCommand).resolves({
        serviceArns: ['arn:aws:ecs:us-east-1:123456789012:service/my-cluster/safe-service'],
      });
      ecsMock.on(DescribeServicesCommand).resolves({
        services: [
          {
            serviceArn: 'arn:aws:ecs:us-east-1:123456789012:service/my-cluster/safe-service',
            serviceName: 'safe-service',
            deploymentConfiguration: { deploymentCircuitBreaker: { enable: true, rollback: true } },
            networkConfiguration: {
              awsvpcConfiguration: { assignPublicIp: 'DISABLED' },
            },
          },
        ],
      });

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.checkId === 'ecs_service_deployment_circuit_breaker_enabled')).toBe(false);
      expect(findings.some(f => f.checkId === 'ecs_service_no_assign_public_ip')).toBe(false);
    });

    it('flags a Fargate service on an outdated platform version', async () => {
      ecsMock.on(ListClustersCommand).resolves({
        clusterArns: ['arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster'],
      });
      ecsMock.on(DescribeClustersCommand).resolves({
        clusters: [
          {
            clusterArn: 'arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster',
            clusterName: 'my-cluster',
            settings: [{ name: 'containerInsights', value: 'enabled' }],
          },
        ],
      });
      ecsMock.on(ListServicesCommand).resolves({
        serviceArns: ['arn:aws:ecs:us-east-1:123456789012:service/my-cluster/fargate-service'],
      });
      ecsMock.on(DescribeServicesCommand).resolves({
        services: [
          {
            serviceArn: 'arn:aws:ecs:us-east-1:123456789012:service/my-cluster/fargate-service',
            serviceName: 'fargate-service',
            deploymentConfiguration: { deploymentCircuitBreaker: { enable: true } },
            networkConfiguration: { awsvpcConfiguration: { assignPublicIp: 'DISABLED' } },
            launchType: 'FARGATE',
            platformFamily: 'LINUX',
            platformVersion: '1.3.0',
          },
        ],
      });

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      const platformFinding = findings.find(f => f.checkId === 'ecs_service_fargate_latest_platform_version');
      expect(platformFinding).toBeDefined();
      expect(platformFinding?.evidence).toMatchObject({
        serviceName: 'fargate-service',
        platformFamily: 'LINUX',
        platformVersion: '1.3.0',
      });
    });

    it('does not flag a Fargate service on platform version LATEST', async () => {
      ecsMock.on(ListClustersCommand).resolves({
        clusterArns: ['arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster'],
      });
      ecsMock.on(DescribeClustersCommand).resolves({
        clusters: [
          {
            clusterArn: 'arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster',
            clusterName: 'my-cluster',
            settings: [{ name: 'containerInsights', value: 'enabled' }],
          },
        ],
      });
      ecsMock.on(ListServicesCommand).resolves({
        serviceArns: ['arn:aws:ecs:us-east-1:123456789012:service/my-cluster/fargate-service'],
      });
      ecsMock.on(DescribeServicesCommand).resolves({
        services: [
          {
            serviceArn: 'arn:aws:ecs:us-east-1:123456789012:service/my-cluster/fargate-service',
            serviceName: 'fargate-service',
            deploymentConfiguration: { deploymentCircuitBreaker: { enable: true } },
            networkConfiguration: { awsvpcConfiguration: { assignPublicIp: 'DISABLED' } },
            launchType: 'FARGATE',
            platformFamily: 'LINUX',
            platformVersion: 'LATEST',
          },
        ],
      });

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings.some(f => f.checkId === 'ecs_service_fargate_latest_platform_version')).toBe(false);
    });

    it('flags a task set that automatically assigns a public IP', async () => {
      ecsMock.on(ListClustersCommand).resolves({
        clusterArns: ['arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster'],
      });
      ecsMock.on(DescribeClustersCommand).resolves({
        clusters: [
          {
            clusterArn: 'arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster',
            clusterName: 'my-cluster',
            settings: [{ name: 'containerInsights', value: 'enabled' }],
          },
        ],
      });
      ecsMock.on(ListServicesCommand).resolves({
        serviceArns: ['arn:aws:ecs:us-east-1:123456789012:service/my-cluster/ts-service'],
      });
      ecsMock.on(DescribeServicesCommand).resolves({
        services: [
          {
            serviceArn: 'arn:aws:ecs:us-east-1:123456789012:service/my-cluster/ts-service',
            serviceName: 'ts-service',
            deploymentConfiguration: { deploymentCircuitBreaker: { enable: true } },
            networkConfiguration: { awsvpcConfiguration: { assignPublicIp: 'DISABLED' } },
            taskSets: [
              {
                id: 'ts-1',
                taskSetArn: 'arn:aws:ecs:us-east-1:123456789012:task-set/my-cluster/ts-service/ts-1',
                networkConfiguration: { awsvpcConfiguration: { assignPublicIp: 'ENABLED' } },
              },
            ],
          },
        ],
      });

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      const taskSetFinding = findings.find(f => f.checkId === 'ecs_task_set_no_assign_public_ip');
      expect(taskSetFinding).toBeDefined();
      expect(taskSetFinding?.evidence).toMatchObject({
        taskSetId: 'ts-1',
        serviceName: 'ts-service',
        clusterName: 'my-cluster',
      });
    });

    it('paginates through ListServicesCommand using nextToken and describes all services across pages', async () => {
      ecsMock.on(ListClustersCommand).resolves({
        clusterArns: ['arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster'],
      });
      ecsMock.on(DescribeClustersCommand).resolves({
        clusters: [
          {
            clusterArn: 'arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster',
            clusterName: 'my-cluster',
            settings: [{ name: 'containerInsights', value: 'enabled' }],
          },
        ],
      });
      ecsMock
        .on(ListServicesCommand)
        .resolvesOnce({
          serviceArns: ['arn:aws:ecs:us-east-1:123456789012:service/my-cluster/service-a'],
          nextToken: 'svc-token-2',
        })
        .resolvesOnce({
          serviceArns: ['arn:aws:ecs:us-east-1:123456789012:service/my-cluster/service-b'],
        });
      ecsMock.on(DescribeServicesCommand).callsFake((input: any) => {
        const services = (input.services as string[]).map((arn) => ({
          serviceArn: arn,
          serviceName: arn.split('/').pop(),
          deploymentConfiguration: {},
          networkConfiguration: { awsvpcConfiguration: { assignPublicIp: 'DISABLED' } },
        }));
        return Promise.resolve({ services });
      });

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      expect(ecsMock.commandCalls(ListServicesCommand)).toHaveLength(2);
      const flaggedServices = findings
        .filter(f => f.checkId === 'ecs_service_deployment_circuit_breaker_enabled')
        .map(f => f.evidence.serviceName)
        .sort();
      expect(flaggedServices).toEqual(['service-a', 'service-b']);
    });

    it('does not throw and returns gracefully when ListClustersCommand fails', async () => {
      ecsMock.on(ListClustersCommand).rejects(new Error('Access Denied'));

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      expect(findings).toEqual([]);
    }, 15000);

    it('does not throw and skips a cluster when ListServicesCommand fails for it', async () => {
      ecsMock.on(ListClustersCommand).resolves({
        clusterArns: ['arn:aws:ecs:us-east-1:123456789012:cluster/broken-cluster'],
      });
      ecsMock.on(DescribeClustersCommand).resolves({
        clusters: [
          {
            clusterArn: 'arn:aws:ecs:us-east-1:123456789012:cluster/broken-cluster',
            clusterName: 'broken-cluster',
            settings: [{ name: 'containerInsights', value: 'enabled' }],
          },
        ],
      });
      ecsMock.on(ListServicesCommand).rejects(new Error('Access Denied'));

      const scanner = new ECSScanner(makeClient());
      const findings = await scanner.scan();

      // Cluster-level check still ran (Container Insights enabled -> no finding);
      // service-level scan for the cluster was skipped without throwing.
      expect(findings.some(f => f.checkId === 'ecs_cluster_container_insights_enabled')).toBe(false);
      expect(findings.some(f => f.checkId?.startsWith('ecs_service'))).toBe(false);
    }, 15000);
  });
});
