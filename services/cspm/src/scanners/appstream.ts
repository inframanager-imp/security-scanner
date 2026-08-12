// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  AppStreamClient,
  DescribeFleetsCommand,
} from '@aws-sdk/client-appstream';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

/** Prowler default: 36000 seconds (10 hours) */
const MAX_SESSION_DURATION_SECONDS = 36000;
/** Prowler default: 300 seconds (5 minutes) */
const MAX_DISCONNECT_TIMEOUT_SECONDS = 300;
/** Prowler default: 600 seconds (10 minutes) */
const MAX_IDLE_DISCONNECT_TIMEOUT_SECONDS = 600;

export class AppStreamScanner extends BaseScanner {
  private appstream: AppStreamClient;

  constructor(client: AWSClient) {
    super(client, 'AppStream');
    this.appstream = new AppStreamClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting AppStream security scan...');

      const fleets = await this.describeFleets();
      for (const fleet of fleets) {
        const fleetName: string = fleet?.Name ?? '';
        if (!fleetName) continue;
        logger.debug(`Scanning AppStream fleet: ${fleetName}`);
        try {
          findings.push(...this.validateFleet(fleet));
        } catch (error) {
          logger.debug(`Failed to scan AppStream fleet ${fleetName}`, { error: (error as Error).message });
        }
      }

      logger.info(`AppStream scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('AppStream scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async describeFleets(): Promise<any[]> {
    const fleets: any[] = [];
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.appstream.send(new DescribeFleetsCommand({ NextToken: nextToken }));
      });
      fleets.push(...(result.Fleets ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return fleets;
  }

  private validateFleet(fleet: any): ScanningResult[] {
    const findings: ScanningResult[] = [];
    const fleetName: string = fleet.Name;
    const fleetArn: string = fleet.Arn ?? fleetName;

    // appstream_fleet_default_internet_access_disabled
    if (fleet.EnableDefaultInternetAccess === true) {
      findings.push(this.emit(
        'appstream_fleet_default_internet_access_disabled',
        { fleet: fleetName, arn: fleetArn, enableDefaultInternetAccess: true },
        {
          message: `AppStream fleet "${fleetName}" has default internet access enabled`,
          remediation: `Disable default internet access on fleet "${fleetName}" and route outbound traffic through a NAT gateway in the fleet VPC`,
        }
      ));
    }

    // appstream_fleet_maximum_session_duration: must be less than 10 hours
    const maxUserDuration: number = fleet.MaxUserDurationInSeconds ?? 0;
    if (!(maxUserDuration < MAX_SESSION_DURATION_SECONDS)) {
      findings.push(this.emit(
        'appstream_fleet_maximum_session_duration',
        { fleet: fleetName, arn: fleetArn, maxUserDurationInSeconds: maxUserDuration, thresholdSeconds: MAX_SESSION_DURATION_SECONDS },
        {
          message: `AppStream fleet "${fleetName}" has the maximum session duration configured for more than 10 hours (${maxUserDuration} seconds)`,
          remediation: `Set MaxUserDurationInSeconds below ${MAX_SESSION_DURATION_SECONDS} on fleet "${fleetName}"`,
        }
      ));
    }

    // appstream_fleet_session_disconnect_timeout: must be 5 minutes or less
    const disconnectTimeout: number = fleet.DisconnectTimeoutInSeconds ?? 0;
    if (disconnectTimeout > MAX_DISCONNECT_TIMEOUT_SECONDS) {
      findings.push(this.emit(
        'appstream_fleet_session_disconnect_timeout',
        { fleet: fleetName, arn: fleetArn, disconnectTimeoutInSeconds: disconnectTimeout, thresholdSeconds: MAX_DISCONNECT_TIMEOUT_SECONDS },
        {
          message: `AppStream fleet "${fleetName}" has the session disconnect timeout set to more than 5 minutes (${disconnectTimeout} seconds)`,
          remediation: `Set DisconnectTimeoutInSeconds to ${MAX_DISCONNECT_TIMEOUT_SECONDS} or less on fleet "${fleetName}"`,
        }
      ));
    }

    // appstream_fleet_session_idle_disconnect_timeout: must be set and 10 minutes or less
    const idleDisconnectTimeout: number | undefined = fleet.IdleDisconnectTimeoutInSeconds;
    if (!(idleDisconnectTimeout && idleDisconnectTimeout <= MAX_IDLE_DISCONNECT_TIMEOUT_SECONDS)) {
      findings.push(this.emit(
        'appstream_fleet_session_idle_disconnect_timeout',
        { fleet: fleetName, arn: fleetArn, idleDisconnectTimeoutInSeconds: idleDisconnectTimeout ?? null, thresholdSeconds: MAX_IDLE_DISCONNECT_TIMEOUT_SECONDS },
        {
          message: `AppStream fleet "${fleetName}" has the session idle disconnect timeout unset or set to more than 10 minutes`,
          remediation: `Set IdleDisconnectTimeoutInSeconds to a value between 1 and ${MAX_IDLE_DISCONNECT_TIMEOUT_SECONDS} on fleet "${fleetName}"`,
        }
      ));
    }

    return findings;
  }
}

export default AppStreamScanner;
