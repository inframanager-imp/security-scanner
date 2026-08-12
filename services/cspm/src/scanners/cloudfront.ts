// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  ListDistributionsCommand,
  GetDistributionConfigCommand,
  type DistributionSummary,
} from '@aws-sdk/client-cloudfront';
import { HeadBucketCommand } from '@aws-sdk/client-s3';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const WEAK_TLS_PROTOCOLS = new Set(['SSLv3', 'TLSv1', 'TLSv1_2016', 'TLSv1.1_2016']);

// TLS 1.3-only security policies that enable quantum-safe key exchange (Prowler default allowlist)
const PQC_TLS_POLICIES = new Set(['TLSv1.3_2025']);

export class CloudFrontScanner extends BaseScanner {
  /** Cache of S3 HeadBucket results — several distributions may share an origin bucket. */
  private bucketExistsCache = new Map<string, boolean>();

  constructor(client: AWSClient) {
    super(client, 'CloudFront');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting CloudFront security scan...');

    const distributions = await this.listDistributions();
    logger.info(`CloudFront: scanning ${distributions.length} distribution(s)`);

    for (const dist of distributions) {
      findings.push(...(await this.scanDistribution(dist)));
    }

    logger.info(`CloudFront scan complete. ${findings.length} findings.`);
    return findings;
  }

  private async listDistributions(): Promise<DistributionSummary[]> {
    const dists: DistributionSummary[] = [];
    let marker: string | undefined;
    try {
      do {
        const result = await retry(() =>
          this.client.cloudfront.send(new ListDistributionsCommand({ Marker: marker, MaxItems: 100 }))
        );
        dists.push(...(result.DistributionList?.Items ?? []));
        marker = result.DistributionList?.IsTruncated ? result.DistributionList?.NextMarker : undefined;
      } while (marker);
    } catch { /* no CloudFront or not us-east-1 */ }
    return dists;
  }

  private async scanDistribution(dist: DistributionSummary): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const id     = dist.Id      ?? 'Unknown';
    const domain = dist.DomainName ?? id;
    const arn    = dist.ARN     ?? id;

    // Fetch full config for logging details
    let config: any = null;
    try {
      const result = await retry(() =>
        this.client.cloudfront.send(new GetDistributionConfigCommand({ Id: id }))
      );
      config = result.DistributionConfig;
    } catch { /* no permission */ }

    // 1. HTTP allowed (not enforced to HTTPS)
    const cacheBehaviors = [
      ...(dist.CacheBehaviors?.Items ?? []),
      dist.DefaultCacheBehavior,
    ].filter(Boolean) as any[];

    const httpAllowed = cacheBehaviors.some(
      cb => cb?.ViewerProtocolPolicy === 'allow-all'
    );
    if (httpAllowed) {
      findings.push(this.emit(
        'cloudfront_distributions_https_enabled',
        { resourceId: arn, distributionId: id, domain },
        {
          message: `CloudFront distribution "${domain}" allows HTTP traffic (ViewerProtocolPolicy: allow-all) on one or more cache behaviors. ` +
            `Data in transit between viewers and CloudFront is not encrypted.`,
        }
      ));
    }

    // 2. No WAF WebACL
    if (!dist.WebACLId) {
      findings.push(this.emit(
        'cloudfront_distributions_using_waf',
        { resourceId: `${arn}::waf`, distributionId: id, domain },
        {
          message: `CloudFront distribution "${domain}" has no WAF WebACL attached. ` +
            `The distribution is exposed to web attacks (OWASP Top 10, bots, DDoS) without WAF protection.`,
        }
      ));
    }

    // 3. Logging disabled
    const loggingEnabled = config?.Logging?.Enabled ?? false;
    if (!loggingEnabled) {
      findings.push(this.emit(
        'cloudfront_distributions_logging_enabled',
        { resourceId: `${arn}::logging`, distributionId: id, domain },
        {
          message: `CloudFront distribution "${domain}" does not have access logging enabled. ` +
            `Without logs, malicious traffic patterns and geographic abuse cannot be analyzed.`,
        }
      ));
    }

    // 4. Weak minimum TLS protocol
    const minProtocol = dist.ViewerCertificate?.MinimumProtocolVersion ?? '';
    if (WEAK_TLS_PROTOCOLS.has(minProtocol)) {
      findings.push(this.emit(
        'cloudfront_distributions_using_deprecated_ssl_protocols',
        { resourceId: `${arn}::tls`, distributionId: id, domain, minimumProtocol: minProtocol },
        {
          message: `CloudFront distribution "${domain}" allows minimum TLS protocol "${minProtocol}". ` +
            `Weak TLS versions (< TLSv1.2) are vulnerable to known attacks (BEAST, POODLE).`,
        }
      ));
    }

    // 5. Default CloudFront domain (no custom certificate)
    const certSource = dist.ViewerCertificate?.CertificateSource ?? '';
    if (certSource === 'cloudfront') {
      findings.push(this.emit(
        'cloudfront_distributions_custom_ssl_certificate',
        { resourceId: `${arn}::cert`, distributionId: id, domain },
        {
          message: `CloudFront distribution "${domain}" uses the default CloudFront SSL certificate instead of a custom ACM certificate. ` +
            `Users will see the generic *.cloudfront.net domain which reduces trust and brand credibility.`,
        }
      ));
    }

    // 6+. Prowler parity checks
    try {
      findings.push(...(await this.runPortedChecks(dist, config)));
    } catch (error) {
      logger.debug(`Failed to run ported checks for CloudFront distribution ${id}`, { error: (error as Error).message });
    }

    return findings;
  }

  /**
   * Checks ported from Prowler. `config` is the full DistributionConfig (may be
   * null when GetDistributionConfig is not permitted); config-dependent checks
   * are skipped in that case to avoid false positives.
   */
  private async runPortedChecks(dist: DistributionSummary, config: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const id     = dist.Id         ?? 'Unknown';
    const domain = dist.DomainName ?? id;
    const arn    = dist.ARN        ?? id;
    const origins: any[] = (dist.Origins?.Items ?? []) as any[];
    const s3Origins = origins.filter(o => o?.S3OriginConfig);
    const viewerProtocolPolicy: string = config?.DefaultCacheBehavior?.ViewerProtocolPolicy ?? '';

    // cloudfront_distributions_default_root_object
    if (config && !config.DefaultRootObject) {
      findings.push(this.emit(
        'cloudfront_distributions_default_root_object',
        { resourceId: `${arn}::rootobject`, distributionId: id, domain },
        {
          message: `CloudFront distribution "${domain}" does not have a default root object configured; root URL requests are forwarded directly to the origin.`,
          remediation: `Set a default root object (e.g. index.html) on distribution "${id}" under Settings > General.`,
        }
      ));
    }

    // cloudfront_distributions_field_level_encryption_enabled
    if (config && !config.DefaultCacheBehavior?.FieldLevelEncryptionId) {
      findings.push(this.emit(
        'cloudfront_distributions_field_level_encryption_enabled',
        { resourceId: `${arn}::fle`, distributionId: id, domain },
        {
          message: `CloudFront distribution "${domain}" does not have field-level encryption enabled on its default cache behavior.`,
          remediation: `Create a field-level encryption configuration and associate it with the default cache behavior of distribution "${id}".`,
        }
      ));
    }

    // cloudfront_distributions_geo_restrictions_enabled
    if (config) {
      const geoRestrictionType: string = config.Restrictions?.GeoRestriction?.RestrictionType ?? 'none';
      if (geoRestrictionType === 'none') {
        findings.push(this.emit(
          'cloudfront_distributions_geo_restrictions_enabled',
          { resourceId: `${arn}::geo`, distributionId: id, domain, restrictionType: geoRestrictionType },
          {
            message: `CloudFront distribution "${domain}" has geo restrictions disabled; content is reachable from every country.`,
            remediation: `Configure a geographic allow list or block list on distribution "${id}" under the Security > Geographic restrictions settings.`,
          }
        ));
      }
    }

    // cloudfront_distributions_https_sni_enabled (only evaluated for custom certificates, like Prowler)
    const certificate = dist.ViewerCertificate?.Certificate ?? '';
    const sslSupportMethod = dist.ViewerCertificate?.SSLSupportMethod ?? 'static-ip';
    if (certificate && sslSupportMethod !== 'sni-only') {
      findings.push(this.emit(
        'cloudfront_distributions_https_sni_enabled',
        { resourceId: `${arn}::sni`, distributionId: id, domain, sslSupportMethod },
        {
          message: `CloudFront distribution "${domain}" is not serving HTTPS requests using SNI (SSL support method: ${sslSupportMethod}).`,
          remediation: `Set Client support to "SNI only" on the viewer certificate settings of distribution "${id}".`,
        }
      ));
    }

    // cloudfront_distributions_multiple_origin_failover_configured
    const originGroups: any[] = (dist.OriginGroups?.Items ?? []) as any[];
    const originFailover =
      originGroups.length > 0 &&
      originGroups.every(og => (og?.Members?.Quantity ?? 0) >= 2);
    if (!originFailover) {
      findings.push(this.emit(
        'cloudfront_distributions_multiple_origin_failover_configured',
        { resourceId: `${arn}::failover`, distributionId: id, domain, originGroupCount: originGroups.length },
        {
          message: `CloudFront distribution "${domain}" does not have an origin group configured with at least 2 origins; the origin is a single point of failure.`,
          remediation: `Create an origin group with a primary and secondary origin on distribution "${id}" and point the cache behavior at the origin group.`,
        }
      ));
    }

    // cloudfront_distributions_origin_traffic_encrypted
    if (config) {
      const unencryptedOrigins: string[] = [];
      for (const origin of origins) {
        if (origin.S3OriginConfig) {
          // For S3 origins Prowler only inspects the viewer protocol policy
          if (viewerProtocolPolicy === 'allow-all') unencryptedOrigins.push(origin.Id);
        } else {
          const originProtocolPolicy: string = origin.CustomOriginConfig?.OriginProtocolPolicy ?? '';
          if (
            originProtocolPolicy === '' ||
            originProtocolPolicy === 'http-only' ||
            (originProtocolPolicy === 'match-viewer' && viewerProtocolPolicy === 'allow-all')
          ) {
            unencryptedOrigins.push(origin.Id);
          }
        }
      }
      if (unencryptedOrigins.length > 0) {
        findings.push(this.emit(
          'cloudfront_distributions_origin_traffic_encrypted',
          { resourceId: `${arn}::origin-encryption`, distributionId: id, domain, unencryptedOrigins },
          {
            message: `CloudFront distribution "${domain}" does not encrypt traffic to origins ${unencryptedOrigins.join(', ')}.`,
            remediation: `Set the origin protocol policy to https-only on the listed origins of distribution "${id}" and use redirect-to-https or https-only as the viewer protocol policy.`,
          }
        ));
      }
    }

    // cloudfront_distributions_pqc_tls_enabled
    const minimumProtocolVersion = dist.ViewerCertificate?.MinimumProtocolVersion ?? '';
    if (dist.ViewerCertificate?.CloudFrontDefaultCertificate) {
      findings.push(this.emit(
        'cloudfront_distributions_pqc_tls_enabled',
        { resourceId: `${arn}::pqc`, distributionId: id, domain, minimumProtocolVersion },
        {
          message: `CloudFront distribution "${domain}" uses the default CloudFront certificate, which pins the security policy to TLSv1 and cannot enable post-quantum TLS.`,
          remediation: `Migrate distribution "${id}" to a custom ACM certificate with SNI and set the security policy to TLSv1.3_2025.`,
        }
      ));
    } else if (!PQC_TLS_POLICIES.has(minimumProtocolVersion)) {
      findings.push(this.emit(
        'cloudfront_distributions_pqc_tls_enabled',
        { resourceId: `${arn}::pqc`, distributionId: id, domain, minimumProtocolVersion },
        {
          message: `CloudFront distribution "${domain}" uses TLS security policy "${minimumProtocolVersion || '<none>'}", which is not in the post-quantum allowlist (TLSv1.3_2025).`,
          remediation: `Set the security policy (MinimumProtocolVersion) of distribution "${id}" to TLSv1.3_2025.`,
        }
      ));
    }

    // cloudfront_distributions_s3_origin_access_control (only for distributions with S3 origins)
    if (s3Origins.length > 0) {
      const s3OriginsWithoutOac = s3Origins
        .filter(o => !(o.OriginAccessControlId))
        .map(o => o.Id);
      if (s3OriginsWithoutOac.length > 0) {
        findings.push(this.emit(
          'cloudfront_distributions_s3_origin_access_control',
          { resourceId: `${arn}::oac`, distributionId: id, domain, s3OriginsWithoutOac },
          {
            message: `CloudFront distribution "${domain}" is not using origin access control (OAC) on S3 origins ${s3OriginsWithoutOac.join(', ')}.`,
            remediation: `Create an Origin Access Control (S3 type, sigv4 signing) and attach it to the listed S3 origins of distribution "${id}".`,
          }
        ));
      }
    }

    // cloudfront_distributions_s3_origin_non_existent_bucket
    const nonExistentBuckets: string[] = [];
    for (const origin of s3Origins) {
      const bucketName = String(origin.DomainName ?? '').split('.s3')[0];
      if (!bucketName) continue;
      if (!(await this.bucketExists(bucketName))) nonExistentBuckets.push(bucketName);
    }
    if (nonExistentBuckets.length > 0) {
      findings.push(this.emit(
        'cloudfront_distributions_s3_origin_non_existent_bucket',
        { resourceId: `${arn}::s3origin`, distributionId: id, domain, nonExistentBuckets },
        {
          message: `CloudFront distribution "${domain}" has non-existent S3 buckets as origins: ${nonExistentBuckets.join(', ')}. The bucket name could be claimed by an attacker (bucket takeover).`,
          remediation: `Remove or update the origins of distribution "${id}" that reference the missing buckets, or recreate the buckets under your ownership.`,
        }
      ));
    }

    return findings;
  }

  /** HeadBucket probe. Only a definitive 404/NotFound counts as non-existent; 403 means the bucket exists in another account. */
  private async bucketExists(bucketName: string): Promise<boolean> {
    const cached = this.bucketExistsCache.get(bucketName);
    if (cached !== undefined) return cached;

    let exists = true;
    try {
      await this.client.s3.send(new HeadBucketCommand({ Bucket: bucketName }));
    } catch (error: any) {
      const statusCode = error?.$metadata?.httpStatusCode;
      if (statusCode === 404 || error?.name === 'NotFound' || error?.name === 'NoSuchBucket') {
        exists = false;
      } else {
        logger.debug(`HeadBucket for CloudFront origin bucket ${bucketName} failed (treating as existing)`, { error: (error as Error).message });
      }
    }
    this.bucketExistsCache.set(bucketName, exists);
    return exists;
  }
}

export default CloudFrontScanner;
