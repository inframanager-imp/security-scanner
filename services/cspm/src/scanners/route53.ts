// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  Route53Client,
  ListHostedZonesCommand,
  ListQueryLoggingConfigsCommand,
  ListResourceRecordSetsCommand,
} from '@aws-sdk/client-route-53';
import {
  Route53DomainsClient,
  ListDomainsCommand,
  GetDomainDetailCommand,
} from '@aws-sdk/client-route-53-domains';
import {
  DescribeAddressesCommand,
  DescribeNetworkInterfacesCommand,
} from '@aws-sdk/client-ec2';
import { ListBucketsCommand } from '@aws-sdk/client-s3';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const AWS_IP_RANGES_URL = 'https://ip-ranges.amazonaws.com/ip-ranges.json';

// S3 website endpoint formats:
//   <bucket>.s3-website-<region>.amazonaws.com   (legacy, dash)
//   <bucket>.s3-website.<region>.amazonaws.com   (newer, dot)
const S3_WEBSITE_ENDPOINT_REGEX = /^(.+)\.s3-website[.-]([a-z0-9-]+)\.amazonaws\.com\.?$/;

interface Ipv4Cidr {
  base: number;
  maskBits: number;
}

function isIpv4(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d{1,3}$/.test(p) && parseInt(p, 10) <= 255);
}

function ipv4ToInt(value: string): number {
  return value.split('.').reduce((acc, octet) => acc * 256 + parseInt(octet, 10), 0);
}

function isPrivateIpv4(value: string): boolean {
  const parts = value.split('.').map((n) => parseInt(n, 10));
  const a = parts[0];
  const b = parts[1];
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127) ||
    a === 0
  );
}

function parseCidr(cidr: string): Ipv4Cidr | null {
  const slash = cidr.split('/');
  if (slash.length !== 2 || !isIpv4(slash[0])) return null;
  const maskBits = parseInt(slash[1], 10);
  if (isNaN(maskBits) || maskBits < 0 || maskBits > 32) return null;
  return { base: ipv4ToInt(slash[0]), maskBits };
}

function ipv4InCidr(ip: string, range: Ipv4Cidr): boolean {
  if (range.maskBits === 0) return true;
  const mask = range.maskBits >= 32 ? 0xffffffff : ((0xffffffff << (32 - range.maskBits)) >>> 0);
  return ((ipv4ToInt(ip) & mask) >>> 0) === ((range.base & mask) >>> 0);
}

export class Route53Scanner extends BaseScanner {
  private route53: Route53Client;
  private route53domains: Route53DomainsClient;

  constructor(client: AWSClient) {
    super(client, 'Route53');
    this.route53 = new Route53Client(client.getClientConfig());
    // The Route53 Domains API is only served from us-east-1
    this.route53domains = new Route53DomainsClient({ ...client.getClientConfig(), region: 'us-east-1' });
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Route53 security scan...');

      const hostedZones = await this.listHostedZones();

      // route53_public_hosted_zones_cloudwatch_logging_enabled
      const loggingFindings = await this.checkQueryLogging(hostedZones);
      findings.push(...loggingFindings);

      // route53_dangling_ip_subdomain_takeover
      const danglingFindings = await this.checkDanglingRecords(hostedZones);
      findings.push(...danglingFindings);

      // route53_domains_transferlock_enabled + route53_domains_privacy_protection_enabled
      const domainFindings = await this.checkRegisteredDomains();
      findings.push(...domainFindings);

      logger.info(`Route53 scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Route53 scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listHostedZones(): Promise<any[]> {
    const zones: any[] = [];
    let marker: string | undefined;
    let truncated = true;
    while (truncated) {
      const result = await retry(async () => {
        return await this.route53.send(new ListHostedZonesCommand({ Marker: marker }));
      });
      zones.push(...(result.HostedZones ?? []));
      truncated = result.IsTruncated === true;
      marker = result.NextMarker;
      if (truncated && !marker) break;
    }
    return zones;
  }

  private async checkQueryLogging(hostedZones: any[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      // Map of hosted zone id -> CloudWatch log group ARN
      const loggingConfigs = new Map<string, string>();
      let nextToken: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.route53.send(new ListQueryLoggingConfigsCommand({ NextToken: nextToken }));
        });
        for (const config of result.QueryLoggingConfigs ?? []) {
          if (config.HostedZoneId) {
            loggingConfigs.set(config.HostedZoneId, config.CloudWatchLogsLogGroupArn ?? '');
          }
        }
        nextToken = result.NextToken;
      } while (nextToken);

      for (const zone of hostedZones) {
        if (zone.Config?.PrivateZone) continue;
        const zoneId = String(zone.Id ?? '').replace('/hostedzone/', '');
        if (!loggingConfigs.has(zoneId)) {
          findings.push(this.emit(
            'route53_public_hosted_zones_cloudwatch_logging_enabled',
            { hostedZoneId: zoneId, zoneName: zone.Name },
            {
              message: `Route53 public hosted zone "${zone.Name}" (${zoneId}) has DNS query logging disabled`,
              remediation: `Enable query logging for hosted zone ${zoneId} to a centralized CloudWatch Logs group`,
            }
          ));
        }
      }
    } catch (error) {
      logger.debug('Failed to check Route53 query logging', { error: (error as Error).message });
    }
    return findings;
  }

  private async listRecordSets(zoneId: string): Promise<any[]> {
    const records: any[] = [];
    let startRecordName: string | undefined;
    let startRecordType: any;
    let startRecordIdentifier: string | undefined;
    let truncated = true;
    while (truncated) {
      const result = await retry(async () => {
        return await this.route53.send(new ListResourceRecordSetsCommand({
          HostedZoneId: zoneId,
          StartRecordName: startRecordName,
          StartRecordType: startRecordType,
          StartRecordIdentifier: startRecordIdentifier,
        }));
      });
      records.push(...(result.ResourceRecordSets ?? []));
      truncated = result.IsTruncated === true;
      startRecordName = result.NextRecordName;
      startRecordType = result.NextRecordType;
      startRecordIdentifier = result.NextRecordIdentifier;
      if (truncated && !startRecordName) break;
    }
    return records;
  }

  /** Elastic IPs and ENI public IPs owned by the account in the scanned region. */
  private async getAccountPublicIps(): Promise<Set<string>> {
    const publicIps = new Set<string>();
    try {
      const addresses = await retry(async () => {
        return await this.client.ec2.send(new DescribeAddressesCommand({}));
      });
      for (const address of addresses.Addresses ?? []) {
        if (address.PublicIp) publicIps.add(address.PublicIp);
      }
    } catch (error) {
      logger.debug('Failed to describe Elastic IPs', { error: (error as Error).message });
    }
    try {
      let nextToken: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.client.ec2.send(new DescribeNetworkInterfacesCommand({ NextToken: nextToken }));
        });
        for (const eni of result.NetworkInterfaces ?? []) {
          const publicIp = (eni as any).Association?.PublicIp;
          if (publicIp) publicIps.add(publicIp);
        }
        nextToken = result.NextToken;
      } while (nextToken);
    } catch (error) {
      logger.debug('Failed to describe network interfaces', { error: (error as Error).message });
    }
    return publicIps;
  }

  private async getOwnedBucketNames(): Promise<Set<string>> {
    const names = new Set<string>();
    try {
      const result = await retry(async () => {
        return await this.client.s3.send(new ListBucketsCommand({}));
      });
      for (const bucket of result.Buckets ?? []) {
        if (bucket.Name) names.add(bucket.Name.toLowerCase());
      }
    } catch (error) {
      logger.debug('Failed to list S3 buckets for dangling CNAME analysis', { error: (error as Error).message });
    }
    return names;
  }

  /** AWS public IPv4 prefixes; empty list when the feed cannot be fetched (A record analysis is then skipped, as in Prowler). */
  private async fetchAwsIpRanges(): Promise<Ipv4Cidr[]> {
    try {
      const fetchFn: any = (globalThis as any).fetch;
      if (typeof fetchFn !== 'function') {
        logger.debug('global fetch unavailable; skipping AWS IP range analysis for dangling A records');
        return [];
      }
      const response = await fetchFn(AWS_IP_RANGES_URL);
      if (!response.ok) {
        logger.debug(`AWS IP ranges feed returned HTTP ${response.status}; skipping dangling A record analysis`);
        return [];
      }
      const data: any = await response.json();
      const ranges: Ipv4Cidr[] = [];
      for (const prefix of data?.prefixes ?? []) {
        if (typeof prefix?.ip_prefix === 'string') {
          const parsed = parseCidr(prefix.ip_prefix);
          if (parsed) ranges.push(parsed);
        }
      }
      return ranges;
    } catch (error) {
      logger.debug('Failed to fetch AWS IP ranges; skipping dangling A record analysis', { error: (error as Error).message });
      return [];
    }
  }

  private async checkDanglingRecords(hostedZones: any[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const accountPublicIps = await this.getAccountPublicIps();
      const ownedBuckets = await this.getOwnedBucketNames();
      // AWS public IP prefixes are fetched lazily, at most once per scan,
      // only when a dangling-candidate public IP is found.
      let awsIpRanges: Ipv4Cidr[] | null = null;

      for (const zone of hostedZones) {
        const zoneId = String(zone.Id ?? '').replace('/hostedzone/', '');
        const zoneName = zone.Name ?? zoneId;
        let records: any[] = [];
        try {
          records = await this.listRecordSets(zoneId);
        } catch (error) {
          logger.debug(`Failed to list record sets for hosted zone ${zoneId}`, { error: (error as Error).message });
          continue;
        }

        for (const record of records) {
          // Alias records point to AWS-managed endpoints and are not takeover candidates here
          if (record.AliasTarget) continue;

          if (record.Type === 'A') {
            // Dangling-IP path: A record pointing to an AWS public IP not allocated to this account
            for (const rr of record.ResourceRecords ?? []) {
              const value: string = rr.Value ?? '';
              if (!isIpv4(value)) continue;
              if (isPrivateIpv4(value) || accountPublicIps.has(value)) continue;
              if (awsIpRanges === null) {
                awsIpRanges = await this.fetchAwsIpRanges();
              }
              if (awsIpRanges.some((range) => ipv4InCidr(value, range))) {
                findings.push(this.emit(
                  'route53_dangling_ip_subdomain_takeover',
                  { hostedZoneId: zoneId, recordName: record.Name, recordType: 'A', value },
                  {
                    message: `Route53 A record "${record.Name}" in hosted zone "${zoneName}" points to ${value}, an AWS public IP not allocated to this account — a dangling IP that can lead to a subdomain takeover attack`,
                    remediation: `Remove or update the A record "${record.Name}" so it no longer points to the unowned IP ${value}; prefer alias records to managed endpoints`,
                  }
                ));
              }
            }
          } else if (record.Type === 'CNAME') {
            // Dangling S3 website endpoint: deleted bucket whose name can be re-registered by anyone
            for (const rr of record.ResourceRecords ?? []) {
              const value: string = (rr.Value ?? '').toLowerCase();
              const match = S3_WEBSITE_ENDPOINT_REGEX.exec(value);
              if (!match) continue;
              const bucketName = match[1];
              if (!ownedBuckets.has(bucketName)) {
                findings.push(this.emit(
                  'route53_dangling_ip_subdomain_takeover',
                  { hostedZoneId: zoneId, recordName: record.Name, recordType: 'CNAME', value, bucketName },
                  {
                    message: `Route53 CNAME "${record.Name}" in hosted zone "${zoneName}" points to the S3 website endpoint of bucket "${bucketName}" which does not exist in the account and can lead to a subdomain takeover attack`,
                    remediation: `Delete the CNAME record "${record.Name}" or re-create the S3 bucket "${bucketName}" in this account`,
                  }
                ));
              }
            }
          }
        }
      }
    } catch (error) {
      logger.debug('Failed to check Route53 dangling records', { error: (error as Error).message });
    }
    return findings;
  }

  private async checkRegisteredDomains(): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    try {
      const domainNames: string[] = [];
      let marker: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.route53domains.send(new ListDomainsCommand({ Marker: marker }));
        });
        for (const domain of result.Domains ?? []) {
          if (domain.DomainName) domainNames.push(domain.DomainName);
        }
        marker = result.NextPageMarker;
      } while (marker);

      for (const domainName of domainNames) {
        try {
          const detail = await retry(async () => {
            return await this.route53domains.send(new GetDomainDetailCommand({ DomainName: domainName }));
          });

          // route53_domains_transferlock_enabled
          const statusList: string[] = detail.StatusList ?? [];
          if (!statusList.includes('clientTransferProhibited')) {
            findings.push(this.emit(
              'route53_domains_transferlock_enabled',
              { domain: domainName, statusList },
              { message: `Route53 registered domain "${domainName}" does not have the transfer lock (clientTransferProhibited) enabled` }
            ));
          }

          // route53_domains_privacy_protection_enabled
          if (!detail.AdminPrivacy) {
            findings.push(this.emit(
              'route53_domains_privacy_protection_enabled',
              { domain: domainName, adminPrivacy: detail.AdminPrivacy ?? false },
              { message: `Route53 registered domain "${domainName}" has public WHOIS contact information (privacy protection disabled)` }
            ));
          }
        } catch (error) {
          logger.debug(`Failed to get detail for Route53 domain ${domainName}`, { error: (error as Error).message });
        }
      }
    } catch (error) {
      // Route53 Domains is only available in the aws partition / us-east-1; treat failures as non-fatal
      logger.debug('Failed to list Route53 registered domains', { error: (error as Error).message });
    }
    return findings;
  }
}

export default Route53Scanner;
