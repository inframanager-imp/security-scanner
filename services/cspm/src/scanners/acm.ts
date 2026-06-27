import {
  ListCertificatesCommand,
  DescribeCertificateCommand,
  type CertificateSummary,
} from '@aws-sdk/client-acm';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const DAYS_30 = 30 * 24 * 60 * 60 * 1000;
const DAYS_7  =  7 * 24 * 60 * 60 * 1000;

export class ACMScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'ACM');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting ACM certificate security scan...');

    const certs = await this.listCertificates();
    logger.info(`ACM: scanning ${certs.length} certificate(s)`);

    for (const cert of certs) {
      findings.push(...(await this.scanCertificate(cert)));
    }

    logger.info(`ACM scan complete. ${findings.length} findings.`);
    return findings;
  }

  private async listCertificates(): Promise<CertificateSummary[]> {
    const certs: CertificateSummary[] = [];
    let nextToken: string | undefined;
    try {
      do {
        const result = await retry(() =>
          this.client.acm.send(new ListCertificatesCommand({ NextToken: nextToken, MaxItems: 100 }))
        );
        certs.push(...(result.CertificateSummaryList ?? []));
        nextToken = result.NextToken;
      } while (nextToken);
    } catch { /* no permission */ }
    return certs;
  }

  private async scanCertificate(summary: CertificateSummary): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const arn    = summary.CertificateArn ?? '';
    const domain = summary.DomainName     ?? 'Unknown';

    let cert: any = null;
    try {
      const result = await retry(() =>
        this.client.acm.send(new DescribeCertificateCommand({ CertificateArn: arn }))
      );
      cert = result.Certificate;
    } catch { return findings; }

    if (!cert) return findings;

    const notAfter  = cert.NotAfter ? new Date(cert.NotAfter).getTime() : null;
    const now       = Date.now();
    const inUse     = (cert.InUseBy ?? []).length > 0;
    const status    = cert.Status ?? '';

    // 1. Certificate expiring within 7 days
    if (notAfter && notAfter - now <= DAYS_7 && notAfter > now) {
      findings.push(this.createFinding(
        'ACM Certificate Expiring Within 7 Days',
        `ACM certificate for "${domain}" expires on ${new Date(notAfter).toISOString().slice(0, 10)}. ` +
        `If not renewed, services using this certificate will show TLS errors to users.`,
        'CRITICAL',
        {
          resourceId:  arn,
          certArn:     arn,
          domain,
          expiresOn:   new Date(notAfter).toISOString(),
          daysRemaining: Math.floor((notAfter - now) / 86400000),
          inUse,
          inUseBy:     cert.InUseBy,
        },
        `Renew the certificate immediately. ACM-managed certificates renew automatically if DNS/email validation is still valid. ` +
        `Verify domain validation records are in place.`,
        ['acm', 'certificate', 'expiry'],
      ));
    }

    // 2. Certificate expiring within 30 days
    else if (notAfter && notAfter - now <= DAYS_30 && notAfter > now) {
      findings.push(this.createFinding(
        'ACM Certificate Expiring Within 30 Days',
        `ACM certificate for "${domain}" expires on ${new Date(notAfter).toISOString().slice(0, 10)} ` +
        `(${Math.floor((notAfter - now) / 86400000)} days remaining). Ensure auto-renewal is configured.`,
        'HIGH',
        {
          resourceId:    arn,
          certArn:       arn,
          domain,
          expiresOn:     new Date(notAfter).toISOString(),
          daysRemaining: Math.floor((notAfter - now) / 86400000),
          inUse,
          inUseBy:       cert.InUseBy,
        },
        `Verify that ACM auto-renewal is active (check domain validation status in ACM console). ` +
        `If using email validation, respond to renewal approval emails.`,
        ['acm', 'certificate', 'expiry'],
      ));
    }

    // 3. Certificate expired
    if (notAfter && notAfter < now) {
      findings.push(this.createFinding(
        'ACM Certificate Expired',
        `ACM certificate for "${domain}" expired on ${new Date(notAfter).toISOString().slice(0, 10)}. ` +
        `${inUse ? 'This certificate is still in use — services will be serving an expired TLS certificate!' : ''}`,
        inUse ? 'CRITICAL' : 'HIGH',
        {
          resourceId: arn,
          certArn:    arn,
          domain,
          expiredOn:  new Date(notAfter).toISOString(),
          inUse,
          inUseBy:    cert.InUseBy,
        },
        `Request a new certificate in ACM for "${domain}" and update all resources using the expired certificate.`,
        ['acm', 'certificate', 'expiry'],
      ));
    }

    // 4. Certificate not in use
    if (status === 'ISSUED' && !inUse) {
      findings.push(this.createFinding(
        'ACM Certificate Issued But Not In Use',
        `ACM certificate for "${domain}" is issued but not associated with any AWS resource (CloudFront, ALB, API Gateway). ` +
        `Unused certificates waste cost and may indicate forgotten resources.`,
        'LOW',
        { resourceId: `${arn}::unused`, certArn: arn, domain, status },
        `Either associate the certificate with a resource or delete it: aws acm delete-certificate --certificate-arn ${arn}`,
        ['acm', 'certificate'],
      ));
    }

    // 5. Validation pending
    if (status === 'PENDING_VALIDATION') {
      findings.push(this.createFinding(
        'ACM Certificate Validation Pending',
        `ACM certificate for "${domain}" is stuck in PENDING_VALIDATION state. ` +
        `The domain validation record (DNS CNAME or email) has not been completed.`,
        'MEDIUM',
        { resourceId: `${arn}::pending`, certArn: arn, domain, status },
        `Complete domain validation by adding the required DNS CNAME record or responding to the validation email.`,
        ['acm', 'certificate'],
      ));
    }

    return findings;
  }
}

export default ACMScanner;
