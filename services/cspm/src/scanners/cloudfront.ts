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
      findings.push(this.createFinding(
        'CloudFront Distribution Allows HTTP Traffic',
        `CloudFront distribution "${domain}" allows HTTP traffic (ViewerProtocolPolicy: allow-all) on one or more cache behaviors. ` +
        `Data in transit between viewers and CloudFront is not encrypted.`,
        'HIGH',
        { resourceId: arn, distributionId: id, domain },
        `Set ViewerProtocolPolicy to "redirect-to-https" or "https-only" on all cache behaviors in CloudFront distribution settings.`,
        ['cloudfront', 'https', 'encryption'],
      ));
    }

    // 2. No WAF WebACL
    if (!dist.WebACLId) {
      findings.push(this.createFinding(
        'CloudFront Distribution Not Protected By WAF',
        `CloudFront distribution "${domain}" has no WAF WebACL attached. ` +
        `The distribution is exposed to web attacks (OWASP Top 10, bots, DDoS) without WAF protection.`,
        'HIGH',
        { resourceId: `${arn}::waf`, distributionId: id, domain },
        `Associate a WAF WebACL (in us-east-1) with this CloudFront distribution via the WAF console or CloudFront settings.`,
        ['cloudfront', 'waf'],
      ));
    }

    // 3. Logging disabled
    const loggingEnabled = config?.Logging?.Enabled ?? false;
    if (!loggingEnabled) {
      findings.push(this.createFinding(
        'CloudFront Distribution Access Logging Disabled',
        `CloudFront distribution "${domain}" does not have access logging enabled. ` +
        `Without logs, malicious traffic patterns and geographic abuse cannot be analyzed.`,
        'MEDIUM',
        { resourceId: `${arn}::logging`, distributionId: id, domain },
        `Enable access logging in CloudFront distribution settings. Specify an S3 bucket as the logging destination.`,
        ['cloudfront', 'logging'],
      ));
    }

    // 4. Weak minimum TLS protocol
    const minProtocol = dist.ViewerCertificate?.MinimumProtocolVersion ?? '';
    if (WEAK_TLS_PROTOCOLS.has(minProtocol)) {
      findings.push(this.createFinding(
        'CloudFront Distribution Uses Weak TLS Protocol',
        `CloudFront distribution "${domain}" allows minimum TLS protocol "${minProtocol}". ` +
        `Weak TLS versions (< TLSv1.2) are vulnerable to known attacks (BEAST, POODLE).`,
        'HIGH',
        { resourceId: `${arn}::tls`, distributionId: id, domain, minimumProtocol: minProtocol },
        `Update minimum TLS protocol to TLSv1.2_2021 in CloudFront viewer certificate settings.`,
        ['cloudfront', 'tls', 'encryption'],
      ));
    }

    // 5. Default CloudFront domain (no custom certificate)
    const certSource = dist.ViewerCertificate?.CertificateSource ?? '';
    if (certSource === 'cloudfront') {
      findings.push(this.createFinding(
        'CloudFront Distribution Using Default SSL Certificate',
        `CloudFront distribution "${domain}" uses the default CloudFront SSL certificate instead of a custom ACM certificate. ` +
        `Users will see the generic *.cloudfront.net domain which reduces trust and brand credibility.`,
        'LOW',
        { resourceId: `${arn}::cert`, distributionId: id, domain },
        `Request a certificate in ACM (us-east-1) and configure it on the CloudFront distribution with a custom domain.`,
        ['cloudfront', 'certificate'],
      ));
    }

    return findings;
  }
}

export default CloudFrontScanner;
