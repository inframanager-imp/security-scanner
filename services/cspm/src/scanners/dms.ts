// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  DatabaseMigrationServiceClient,
  DescribeReplicationInstancesCommand,
  DescribeEndpointsCommand,
  DescribeReplicationTasksCommand,
} from '@aws-sdk/client-database-migration-service';
import { DescribeSecurityGroupsCommand } from '@aws-sdk/client-ec2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const MINIMUM_SEVERITY_LEVELS = [
  'LOGGER_SEVERITY_DEFAULT',
  'LOGGER_SEVERITY_DEBUG',
  'LOGGER_SEVERITY_DETAILED_DEBUG',
];

export class DMSScanner extends BaseScanner {
  private dms: DatabaseMigrationServiceClient;

  constructor(client: AWSClient) {
    super(client, 'DMS');
    this.dms = new DatabaseMigrationServiceClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting DMS security scan...');

      try {
        findings.push(...await this.checkReplicationInstances());
      } catch (error) {
        logger.debug('Failed to scan DMS replication instances', { error: (error as Error).message });
      }

      try {
        findings.push(...await this.checkEndpoints());
      } catch (error) {
        logger.debug('Failed to scan DMS endpoints', { error: (error as Error).message });
      }

      try {
        findings.push(...await this.checkReplicationTasks());
      } catch (error) {
        logger.debug('Failed to scan DMS replication tasks', { error: (error as Error).message });
      }

      logger.info(`DMS scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('DMS scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async checkReplicationInstances(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const instances: any[] = [];
    let marker: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.dms.send(new DescribeReplicationInstancesCommand({ Marker: marker }));
      });
      instances.push(...(result.ReplicationInstances ?? []));
      marker = result.Marker;
    } while (marker);

    for (const instance of instances) {
      const instanceId: string = instance.ReplicationInstanceIdentifier ?? '';
      logger.debug(`Scanning DMS replication instance: ${instanceId}`);
      try {
        // dms_instance_minor_version_upgrade_enabled
        if (!instance.AutoMinorVersionUpgrade) {
          findings.push(this.emit(
            'dms_instance_minor_version_upgrade_enabled',
            { instanceId, instanceArn: instance.ReplicationInstanceArn, autoMinorVersionUpgrade: false },
            {
              message: `DMS replication instance "${instanceId}" does not have auto minor version upgrade enabled`,
            }
          ));
        }

        // dms_instance_multi_az_enabled
        if (!instance.MultiAZ) {
          findings.push(this.emit(
            'dms_instance_multi_az_enabled',
            { instanceId, instanceArn: instance.ReplicationInstanceArn, multiAZ: false },
            {
              message: `DMS replication instance "${instanceId}" does not have Multi-AZ enabled`,
            }
          ));
        }

        // dms_instance_no_public_access: publicly accessible AND a security group open to the Internet
        if (instance.PubliclyAccessible) {
          const activeSecurityGroups: string[] = (instance.VpcSecurityGroups ?? [])
            .filter((sg: any) => sg.Status === 'active' && sg.VpcSecurityGroupId)
            .map((sg: any) => sg.VpcSecurityGroupId);
          if (activeSecurityGroups.length > 0) {
            const openGroup = await this.findSecurityGroupOpenToInternet(activeSecurityGroups);
            if (openGroup) {
              findings.push(this.emit(
                'dms_instance_no_public_access',
                {
                  instanceId,
                  instanceArn: instance.ReplicationInstanceArn,
                  publiclyAccessible: true,
                  securityGroups: activeSecurityGroups,
                  openSecurityGroup: openGroup,
                },
                {
                  message: `DMS replication instance "${instanceId}" is set as publicly accessible and security group ${openGroup} is open to the Internet`,
                }
              ));
            }
          }
        }
      } catch (error) {
        logger.debug(`Failed to scan DMS replication instance ${instanceId}`, { error: (error as Error).message });
      }
    }

    return findings;
  }

  /** Returns the id of the first security group with an ingress rule open to 0.0.0.0/0 or ::/0, or null. */
  private async findSecurityGroupOpenToInternet(groupIds: string[]): Promise<string | null> {
    const result = await retry(async () => {
      return await this.client.ec2.send(new DescribeSecurityGroupsCommand({ GroupIds: groupIds }));
    });
    for (const group of result.SecurityGroups ?? []) {
      for (const rule of group.IpPermissions ?? []) {
        if (this.isIngressRuleOpenToInternet(rule)) {
          return group.GroupId ?? null;
        }
      }
    }
    return null;
  }

  /** Ports Prowler's check_security_group(rule, '-1', any_address=True, all_ports=True). */
  private isIngressRuleOpenToInternet(rule: any): boolean {
    const hasAnyIpv4 = (rule.IpRanges ?? []).some((r: any) => r.CidrIp === '0.0.0.0/0');
    const hasAnyIpv6 = (rule.Ipv6Ranges ?? []).some((r: any) => r.CidrIpv6 === '::/0');
    if (!hasAnyIpv4 && !hasAnyIpv6) return false;
    // All-traffic rules, or protocol rules with a port range, count as open when reachable from any address
    return rule.IpProtocol === '-1' || rule.FromPort !== undefined;
  }

  private async checkEndpoints(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const endpoints: any[] = [];
    let marker: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.dms.send(new DescribeEndpointsCommand({ Marker: marker }));
      });
      endpoints.push(...(result.Endpoints ?? []));
      marker = result.Marker;
    } while (marker);

    for (const endpoint of endpoints) {
      const endpointId: string = endpoint.EndpointIdentifier ?? '';
      const engineName: string = endpoint.EngineName ?? '';
      logger.debug(`Scanning DMS endpoint: ${endpointId}`);
      try {
        // dms_endpoint_ssl_enabled
        const sslMode: string = endpoint.SslMode ?? 'none';
        if (sslMode === 'none') {
          findings.push(this.emit(
            'dms_endpoint_ssl_enabled',
            { endpointId, endpointArn: endpoint.EndpointArn, engineName, sslMode },
            {
              message: `DMS endpoint "${endpointId}" is not using SSL`,
            }
          ));
        }

        // dms_endpoint_mongodb_authentication_enabled
        if (engineName === 'mongodb') {
          const authType: string = endpoint.MongoDbSettings?.AuthType ?? 'no';
          if (authType === 'no') {
            findings.push(this.emit(
              'dms_endpoint_mongodb_authentication_enabled',
              { endpointId, endpointArn: endpoint.EndpointArn, engineName, authType },
              {
                message: `DMS endpoint "${endpointId}" for MongoDB does not have an authentication mechanism enabled`,
              }
            ));
          }
        }

        // dms_endpoint_neptune_iam_authorization_enabled
        if (engineName === 'neptune') {
          const iamAuthEnabled: boolean = endpoint.NeptuneSettings?.IamAuthEnabled ?? false;
          if (!iamAuthEnabled) {
            findings.push(this.emit(
              'dms_endpoint_neptune_iam_authorization_enabled',
              { endpointId, endpointArn: endpoint.EndpointArn, engineName, iamAuthEnabled: false },
              {
                message: `DMS endpoint "${endpointId}" for Neptune does not have IAM authorization enabled`,
              }
            ));
          }
        }

        // dms_endpoint_redis_in_transit_encryption_enabled
        if (engineName === 'redis') {
          const sslSecurityProtocol: string = endpoint.RedisSettings?.SslSecurityProtocol ?? 'plaintext';
          if (sslSecurityProtocol !== 'ssl-encryption') {
            findings.push(this.emit(
              'dms_endpoint_redis_in_transit_encryption_enabled',
              { endpointId, endpointArn: endpoint.EndpointArn, engineName, sslSecurityProtocol },
              {
                message: `DMS endpoint "${endpointId}" for Redis OSS is not encrypted in transit`,
              }
            ));
          }
        }
      } catch (error) {
        logger.debug(`Failed to scan DMS endpoint ${endpointId}`, { error: (error as Error).message });
      }
    }

    return findings;
  }

  private async checkReplicationTasks(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const tasks: any[] = [];
    let marker: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.dms.send(new DescribeReplicationTasksCommand({ Marker: marker }));
      });
      tasks.push(...(result.ReplicationTasks ?? []));
      marker = result.Marker;
    } while (marker);

    for (const task of tasks) {
      const taskId: string = task.ReplicationTaskIdentifier ?? '';
      logger.debug(`Scanning DMS replication task: ${taskId}`);
      try {
        let loggingEnabled = false;
        let logComponents: any[] = [];
        try {
          const settings = JSON.parse(task.ReplicationTaskSettings ?? '{}');
          loggingEnabled = settings.Logging?.EnableLogging ?? false;
          logComponents = settings.Logging?.LogComponents ?? [];
        } catch {
          logger.debug(`Failed to parse replication task settings for DMS task ${taskId}`);
        }

        const componentCompliant = (componentId: string): boolean => {
          return logComponents.some(
            (c: any) => c?.Id === componentId && MINIMUM_SEVERITY_LEVELS.includes(c?.Severity)
          );
        };

        // dms_replication_task_source_logging_enabled
        if (!loggingEnabled) {
          findings.push(this.emit(
            'dms_replication_task_source_logging_enabled',
            { taskId, taskArn: task.ReplicationTaskArn, loggingEnabled: false },
            {
              message: `DMS replication task "${taskId}" does not have logging enabled for source events`,
            }
          ));
        } else {
          const missingSource: string[] = [];
          if (!componentCompliant('SOURCE_CAPTURE')) missingSource.push('SOURCE_CAPTURE');
          if (!componentCompliant('SOURCE_UNLOAD')) missingSource.push('SOURCE_UNLOAD');
          if (missingSource.length > 0) {
            findings.push(this.emit(
              'dms_replication_task_source_logging_enabled',
              { taskId, taskArn: task.ReplicationTaskArn, loggingEnabled: true, missingComponents: missingSource },
              {
                message: `DMS replication task "${taskId}" does not meet the minimum logging severity for ${missingSource.join(' and ')} events`,
              }
            ));
          }
        }

        // dms_replication_task_target_logging_enabled
        if (!loggingEnabled) {
          findings.push(this.emit(
            'dms_replication_task_target_logging_enabled',
            { taskId, taskArn: task.ReplicationTaskArn, loggingEnabled: false },
            {
              message: `DMS replication task "${taskId}" does not have logging enabled for target events`,
            }
          ));
        } else {
          const missingTarget: string[] = [];
          if (!componentCompliant('TARGET_APPLY')) missingTarget.push('TARGET_APPLY');
          if (!componentCompliant('TARGET_LOAD')) missingTarget.push('TARGET_LOAD');
          if (missingTarget.length > 0) {
            findings.push(this.emit(
              'dms_replication_task_target_logging_enabled',
              { taskId, taskArn: task.ReplicationTaskArn, loggingEnabled: true, missingComponents: missingTarget },
              {
                message: `DMS replication task "${taskId}" does not meet the minimum logging severity for ${missingTarget.join(' and ')} events`,
              }
            ));
          }
        }
      } catch (error) {
        logger.debug(`Failed to scan DMS replication task ${taskId}`, { error: (error as Error).message });
      }
    }

    return findings;
  }
}

export default DMSScanner;
