// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  LightsailClient,
  GetInstancesCommand,
  GetRelationalDatabasesCommand,
  GetStaticIpsCommand,
} from '@aws-sdk/client-lightsail';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class LightsailScanner extends BaseScanner {
  private lightsail: LightsailClient;

  constructor(client: AWSClient) {
    super(client, 'Lightsail');
    this.lightsail = new LightsailClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Lightsail security scan...');

      try {
        const instances = await this.getInstances();
        for (const instance of instances) {
          try {
            findings.push(...this.validateInstance(instance));
          } catch (error) {
            logger.debug(`Failed to scan Lightsail instance ${instance?.name}`, { error: (error as Error).message });
          }
        }
      } catch (error) {
        logger.debug('Failed to list Lightsail instances', { error: (error as Error).message });
      }

      try {
        const databases = await this.getRelationalDatabases();
        for (const database of databases) {
          try {
            findings.push(...this.validateDatabase(database));
          } catch (error) {
            logger.debug(`Failed to scan Lightsail database ${database?.name}`, { error: (error as Error).message });
          }
        }
      } catch (error) {
        logger.debug('Failed to list Lightsail databases', { error: (error as Error).message });
      }

      try {
        const staticIps = await this.getStaticIps();
        for (const staticIp of staticIps) {
          try {
            findings.push(...this.validateStaticIp(staticIp));
          } catch (error) {
            logger.debug(`Failed to scan Lightsail static IP ${staticIp?.name}`, { error: (error as Error).message });
          }
        }
      } catch (error) {
        logger.debug('Failed to list Lightsail static IPs', { error: (error as Error).message });
      }

      logger.info(`Lightsail scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Lightsail scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async getInstances(): Promise<any[]> {
    const instances: any[] = [];
    let pageToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.lightsail.send(new GetInstancesCommand({ pageToken }));
      });
      instances.push(...(result.instances ?? []));
      pageToken = result.nextPageToken;
    } while (pageToken);
    return instances;
  }

  private async getRelationalDatabases(): Promise<any[]> {
    const databases: any[] = [];
    let pageToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.lightsail.send(new GetRelationalDatabasesCommand({ pageToken }));
      });
      databases.push(...(result.relationalDatabases ?? []));
      pageToken = result.nextPageToken;
    } while (pageToken);
    return databases;
  }

  private async getStaticIps(): Promise<any[]> {
    const staticIps: any[] = [];
    let pageToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.lightsail.send(new GetStaticIpsCommand({ pageToken }));
      });
      staticIps.push(...(result.staticIps ?? []));
      pageToken = result.nextPageToken;
    } while (pageToken);
    return staticIps;
  }

  private formatPortRange(port: any): string {
    if (port.fromPort === undefined || port.fromPort === null) return '';
    if (port.fromPort === port.toPort) return `${port.fromPort}`;
    return `${port.fromPort}-${port.toPort}`;
  }

  private validateInstance(instance: any): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const name: string = instance.name ?? '';

    // lightsail_instance_public: public IP plus firewall ports open to any IPv4 address
    const publicIp: string = instance.publicIpAddress ?? '';
    const ports: any[] = instance.networking?.ports ?? [];
    const openPublicPorts = ports.filter((port) => port.accessType === 'public');
    if (publicIp !== '' && openPublicPorts.length > 0) {
      const openRanges = openPublicPorts.map((port) => this.formatPortRange(port));
      findings.push(this.emit(
        'lightsail_instance_public',
        {
          instance: name,
          arn: instance.arn,
          publicIpAddress: publicIp,
          openPublicPorts: openPublicPorts.map((port) => ({
            range: this.formatPortRange(port),
            protocol: port.protocol ?? '',
            accessFrom: port.accessFrom ?? '',
          })),
        },
        {
          message: `Lightsail instance "${name}" is publicly exposed. The open ports are: ${openRanges.join(', ')}`,
          remediation: `Restrict the firewall rules of instance "${name}" to trusted source IPs or close the publicly open ports`,
        }
      ));
    }

    // lightsail_instance_automated_snapshots: AutoSnapshot add-on must be enabled
    const addOns: any[] = instance.addOns ?? [];
    const autoSnapshotEnabled = addOns.some(
      (addOn) => addOn?.name === 'AutoSnapshot' && addOn?.status === 'Enabled'
    );
    if (!autoSnapshotEnabled) {
      findings.push(this.emit(
        'lightsail_instance_automated_snapshots',
        { instance: name, arn: instance.arn, autoSnapshot: false },
        {
          message: `Lightsail instance "${name}" does not have automated snapshots enabled`,
          remediation: `Enable the automatic snapshots add-on on instance "${name}"`,
        }
      ));
    }

    return findings;
  }

  private validateDatabase(database: any): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const name: string = database.name ?? '';

    // lightsail_database_public: fail unless public access is explicitly disabled
    if (database.publiclyAccessible !== false) {
      findings.push(this.emit(
        'lightsail_database_public',
        {
          database: name,
          arn: database.arn,
          engine: database.engine ?? '',
          publiclyAccessible: database.publiclyAccessible ?? true,
        },
        {
          message: `Lightsail database "${name}" is public`,
          remediation: `Disable public mode on database "${name}" and connect privately from Lightsail resources or via VPC peering`,
        }
      ));
    }

    return findings;
  }

  private validateStaticIp(staticIp: any): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const name: string = staticIp.name ?? '';

    // lightsail_static_ip_unused: fail only when the API explicitly reports it unattached
    if (staticIp.isAttached === false) {
      findings.push(this.emit(
        'lightsail_static_ip_unused',
        { staticIp: name, arn: staticIp.arn, ipAddress: staticIp.ipAddress ?? '', isAttached: false },
        {
          message: `Lightsail static IP "${name}" is not associated with any instance`,
          remediation: `Attach static IP "${name}" to an instance or release it`,
        }
      ));
    }

    return findings;
  }
}

export default LightsailScanner;
