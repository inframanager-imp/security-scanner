// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  DirectoryServiceClient,
  DescribeDirectoriesCommand,
  ListLogSubscriptionsCommand,
  DescribeEventTopicsCommand,
  ListCertificatesCommand,
  GetSnapshotLimitsCommand,
} from '@aws-sdk/client-directory-service';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

/** Remaining manual snapshots at (or under) which the limit is considered "about to be reached" */
const SNAPSHOT_LIMIT_THRESHOLD = 2;
/** Days before certificate expiration at which a finding is raised */
const CERT_DAYS_TO_EXPIRE_THRESHOLD = 90;
const RECOMMENDED_RADIUS_PROTOCOL = 'MS-CHAPv2';

export class DirectoryServiceScanner extends BaseScanner {
  private ds: DirectoryServiceClient;

  constructor(client: AWSClient) {
    super(client, 'DirectoryService');
    this.ds = new DirectoryServiceClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting DirectoryService security scan...');

      const directories = await this.describeDirectories();
      for (const directory of directories) {
        const directoryId: string = directory?.DirectoryId ?? '';
        if (!directoryId) continue;
        logger.debug(`Scanning Directory Service directory: ${directoryId}`);
        try {
          const directoryFindings = await this.validateDirectory(directory);
          findings.push(...directoryFindings);
        } catch (error) {
          logger.debug(`Failed to scan Directory Service directory ${directoryId}`, { error: (error as Error).message });
        }
      }

      logger.info(`DirectoryService scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('DirectoryService scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async describeDirectories(): Promise<any[]> {
    const directories: any[] = [];
    let nextToken: string | undefined;
    do {
      const result: any = await retry(async () => {
        return await this.ds.send(new DescribeDirectoriesCommand({ NextToken: nextToken }));
      });
      directories.push(...(result.DirectoryDescriptions ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return directories;
  }

  private async validateDirectory(directory: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const directoryId: string = directory.DirectoryId;
    const directoryName: string = directory.Name ?? directoryId;
    const directoryType: string = directory.Type ?? '';

    // directoryservice_directory_log_forwarding_enabled: at least one CloudWatch log subscription
    const logSubscriptions = await this.listLogSubscriptions(directoryId);
    if (logSubscriptions !== null && logSubscriptions.length === 0) {
      findings.push(this.emit(
        'directoryservice_directory_log_forwarding_enabled',
        { directoryId, directoryName, directoryType, logSubscriptions: [] },
        {
          message: `Directory Service directory "${directoryId}" has log forwarding to CloudWatch Logs disabled`,
          remediation: `Create a CloudWatch Logs log subscription for directory "${directoryId}" so domain controller security logs are forwarded and retained`,
        }
      ));
    }

    // directoryservice_directory_monitor_notifications: at least one SNS event topic registered.
    // DescribeEventTopics is not supported for SharedMicrosoftAD directories (Prowler skips the
    // call there and consequently reports FAIL); we skip the check entirely for shared directories.
    if (directoryType !== 'SharedMicrosoftAD') {
      const eventTopics = await this.describeEventTopics(directoryId);
      if (eventTopics !== null && eventTopics.length === 0) {
        findings.push(this.emit(
          'directoryservice_directory_monitor_notifications',
          { directoryId, directoryName, directoryType, eventTopics: [] },
          {
            message: `Directory Service directory "${directoryId}" does not have SNS status notifications enabled`,
            remediation: `Register an SNS topic for directory "${directoryId}" (RegisterEventTopic) so health and status changes generate notifications`,
          }
        ));
      }
    }

    // directoryservice_ldap_certificate_expiration: registered certificates must be valid for
    // more than 90 days. LDAPS operations are not supported for SimpleAD directories.
    if (directoryType !== 'SimpleAD') {
      const certificates = await this.listCertificates(directoryId);
      for (const certificate of certificates ?? []) {
        const expiry: Date | undefined = certificate?.ExpiryDateTime;
        if (!expiry) continue;
        const remainingDays = Math.floor((expiry.getTime() - Date.now()) / 86400000);
        if (remainingDays <= CERT_DAYS_TO_EXPIRE_THRESHOLD) {
          findings.push(this.emit(
            'directoryservice_ldap_certificate_expiration',
            {
              directoryId,
              certificateId: certificate.CertificateId,
              commonName: certificate.CommonName,
              certificateType: certificate.Type,
              expiryDateTime: expiry.toISOString(),
              remainingDays,
            },
            {
              message: `LDAP certificate "${certificate.CertificateId}" configured at directory "${directoryId}" is about to expire in ${remainingDays} days`,
              remediation: `Renew and register a replacement certificate for directory "${directoryId}", then deregister certificate "${certificate.CertificateId}" before it expires`,
            }
          ));
        }
      }
    }

    // directoryservice_directory_snapshots_limit: only MicrosoftAD directories expose snapshot limits
    if (directoryType === 'MicrosoftAD') {
      const snapshotLimits = await this.getSnapshotLimits(directoryId);
      if (snapshotLimits) {
        const limit: number = snapshotLimits.ManualSnapshotsLimit ?? 0;
        const current: number = snapshotLimits.ManualSnapshotsCurrentCount ?? 0;
        if (snapshotLimits.ManualSnapshotsLimitReached) {
          findings.push(this.emit(
            'directoryservice_directory_snapshots_limit',
            { directoryId, manualSnapshotsLimit: limit, manualSnapshotsCurrentCount: current, limitReached: true },
            {
              message: `Directory Service directory "${directoryId}" reached its manual snapshot limit of ${limit}`,
            }
          ));
        } else if (limit - current <= SNAPSHOT_LIMIT_THRESHOLD) {
          findings.push(this.emit(
            'directoryservice_directory_snapshots_limit',
            { directoryId, manualSnapshotsLimit: limit, manualSnapshotsCurrentCount: current, limitReached: false },
            {
              message: `Directory Service directory "${directoryId}" is about to reach its manual snapshot limit of ${limit} (currently using ${current})`,
            }
          ));
        }
      }
    }

    // directoryservice_radius_server_security_protocol: when a RADIUS server is configured,
    // it must use MS-CHAPv2 (PAP, CHAP and MS-CHAPv1 are weak).
    const radiusSettings: any = directory.RadiusSettings;
    if (radiusSettings) {
      const protocol: string | undefined = radiusSettings.AuthenticationProtocol;
      if (protocol !== RECOMMENDED_RADIUS_PROTOCOL) {
        findings.push(this.emit(
          'directoryservice_radius_server_security_protocol',
          { directoryId, directoryName, authenticationProtocol: protocol ?? null },
          {
            message: `RADIUS server of directory "${directoryId}" does not use the recommended MS-CHAPv2 security protocol (current: ${protocol ?? 'not set'})`,
            remediation: `Reconfigure the RADIUS settings of directory "${directoryId}" to use MS-CHAPv2 on both AWS and the RADIUS server`,
          }
        ));
      }
    }

    // directoryservice_supported_mfa_radius_enabled: RADIUS MFA must be enabled and Completed
    // (directories without any RADIUS configuration fail, matching Prowler).
    const radiusStatus: string | undefined = directory.RadiusStatus;
    if (radiusStatus !== 'Completed') {
      findings.push(this.emit(
        'directoryservice_supported_mfa_radius_enabled',
        { directoryId, directoryName, radiusStatus: radiusStatus ?? null },
        {
          message: `Directory Service directory "${directoryId}" does not have RADIUS MFA enabled`,
          remediation: `Configure a RADIUS MFA server for directory "${directoryId}" (EnableRadius) and verify its status reaches Completed`,
        }
      ));
    }

    return findings;
  }

  /** Returns null when the subscriptions could not be listed (check is skipped). */
  private async listLogSubscriptions(directoryId: string): Promise<any[] | null> {
    try {
      const subscriptions: any[] = [];
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.ds.send(new ListLogSubscriptionsCommand({ DirectoryId: directoryId, NextToken: nextToken }));
        });
        subscriptions.push(...(result.LogSubscriptions ?? []));
        nextToken = result.NextToken;
      } while (nextToken);
      return subscriptions;
    } catch (error) {
      logger.debug(`Failed to list log subscriptions for directory ${directoryId}`, { error: (error as Error).message });
      return null;
    }
  }

  /** Returns null when the event topics could not be described (check is skipped). */
  private async describeEventTopics(directoryId: string): Promise<any[] | null> {
    try {
      const result: any = await retry(async () => {
        return await this.ds.send(new DescribeEventTopicsCommand({ DirectoryId: directoryId }));
      });
      return result.EventTopics ?? [];
    } catch (error) {
      logger.debug(`Failed to describe event topics for directory ${directoryId}`, { error: (error as Error).message });
      return null;
    }
  }

  /** Returns null when certificates could not be listed (e.g. UnsupportedOperationException). */
  private async listCertificates(directoryId: string): Promise<any[] | null> {
    try {
      const certificates: any[] = [];
      let nextToken: string | undefined;
      do {
        const result: any = await retry(async () => {
          return await this.ds.send(new ListCertificatesCommand({ DirectoryId: directoryId, NextToken: nextToken }));
        });
        certificates.push(...(result.CertificatesInfo ?? []));
        nextToken = result.NextToken;
      } while (nextToken);
      return certificates;
    } catch (error) {
      logger.debug(`Failed to list certificates for directory ${directoryId}`, { error: (error as Error).message });
      return null;
    }
  }

  /** Returns null when the snapshot limits could not be fetched (check is skipped). */
  private async getSnapshotLimits(directoryId: string): Promise<any | null> {
    try {
      const result: any = await retry(async () => {
        return await this.ds.send(new GetSnapshotLimitsCommand({ DirectoryId: directoryId }));
      });
      return result.SnapshotLimits ?? null;
    } catch (error) {
      logger.debug(`Failed to get snapshot limits for directory ${directoryId}`, { error: (error as Error).message });
      return null;
    }
  }
}

export default DirectoryServiceScanner;
