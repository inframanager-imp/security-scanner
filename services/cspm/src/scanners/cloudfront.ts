import {
  ListDistributionsCommand,
  GetDistributionConfigCommand,
  type DistributionSummary,
} from '@aws-sdk/client-cloudfront';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const WEAK_TLS_PROTOCOLS = new Set(['SSLv3', 'TLSv1', 'TLSv1_2016', 'TLSv1.1_2016']);

export class CloudFrontScanner extends BaseScanner {
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

    return findings;
  }
}

export default CloudFrontScanner;
