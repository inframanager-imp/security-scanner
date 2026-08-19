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
      findings.push(this.emit(
        'acm_certificates_expiration_check',
        {
          resourceId:  arn,
          certArn:     arn,
          domain,
          expiresOn:   new Date(notAfter).toISOString(),
          daysRemaining: Math.floor((notAfter - now) / 86400000),
          inUse,
          inUseBy:     cert.InUseBy,
        },
        {
          message: `ACM certificate for "${domain}" expires on ${new Date(notAfter).toISOString().slice(0, 10)}. ` +
            `If not renewed, services using this certificate will show TLS errors to users.`,
        }
      ));
    }

    // 2. Certificate expiring within 30 days
    else if (notAfter && notAfter - now <= DAYS_30 && notAfter > now) {
      findings.push(this.emit(
        'acm_certificate_expiration_30_days',
        {
          resourceId:    arn,
          certArn:       arn,
          domain,
          expiresOn:     new Date(notAfter).toISOString(),
          daysRemaining: Math.floor((notAfter - now) / 86400000),
          inUse,
          inUseBy:       cert.InUseBy,
        },
        {
          message: `ACM certificate for "${domain}" expires on ${new Date(notAfter).toISOString().slice(0, 10)} ` +
            `(${Math.floor((notAfter - now) / 86400000)} days remaining). Ensure auto-renewal is configured.`,
        }
      ));
    }

    // 3. Certificate expired
    if (notAfter && notAfter < now) {
      findings.push(this.emit(
        'acm_certificate_expired',
        {
          resourceId: arn,
          certArn:    arn,
          domain,
          expiredOn:  new Date(notAfter).toISOString(),
          inUse,
          inUseBy:    cert.InUseBy,
        },
        {
          message: `ACM certificate for "${domain}" expired on ${new Date(notAfter).toISOString().slice(0, 10)}. ` +
            `${inUse ? 'This certificate is still in use — services will be serving an expired TLS certificate!' : ''}`,
          remediation: `Request a new certificate in ACM for "${domain}" and update all resources using the expired certificate.`,
          severity: inUse ? 'CRITICAL' : 'HIGH',
        }
      ));
    }

    // 4. Certificate not in use
    if (status === 'ISSUED' && !inUse) {
      findings.push(this.emit(
        'acm_certificate_not_in_use',
        { resourceId: `${arn}::unused`, certArn: arn, domain, status },
        {
          message: `ACM certificate for "${domain}" is issued but not associated with any AWS resource (CloudFront, ALB, API Gateway). ` +
            `Unused certificates waste cost and may indicate forgotten resources.`,
          remediation: `Either associate the certificate with a resource or delete it: aws acm delete-certificate --certificate-arn ${arn}`,
        }
      ));
    }

    // 5. Validation pending
    if (status === 'PENDING_VALIDATION') {
      findings.push(this.emit(
        'acm_certificate_validation_pending',
        { resourceId: `${arn}::pending`, certArn: arn, domain, status },
        {
          message: `ACM certificate for "${domain}" is stuck in PENDING_VALIDATION state. ` +
            `The domain validation record (DNS CNAME or email) has not been completed.`,
        }
      ));
    }

    return findings;
  }
}

export default ACMScanner;
