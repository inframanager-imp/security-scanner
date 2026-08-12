// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  ACMPCAClient,
  ListCertificateAuthoritiesCommand,
} from '@aws-sdk/client-acm-pca';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Post-quantum (ML-DSA, NIST FIPS 204) key algorithms accepted by Prowler's default allowlist
const PQC_KEY_ALGORITHMS = ['ML_DSA_44', 'ML_DSA_65', 'ML_DSA_87'];

export class ACMPCAScanner extends BaseScanner {
  private acmpca: ACMPCAClient;

  constructor(client: AWSClient) {
    super(client, 'ACM-PCA');
    this.acmpca = new ACMPCAClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting ACM-PCA security scan...');

      const cas = await this.listCertificateAuthorities();
      for (const ca of cas) {
        try {
          findings.push(...this.validateCertificateAuthority(ca));
        } catch (error) {
          logger.debug(`Failed to scan ACM-PCA certificate authority ${ca?.Arn}`, { error: (error as Error).message });
        }
      }

      logger.info(`ACM-PCA scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('ACM-PCA scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listCertificateAuthorities(): Promise<any[]> {
    const cas: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.acmpca.send(new ListCertificateAuthoritiesCommand({ NextToken: nextToken }));
      });
      cas.push(...(result.CertificateAuthorities ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return cas;
  }

  private validateCertificateAuthority(ca: any): ScanningResult[] {
    const findings: ScanningResult[] = [];

    const arn: string = ca.Arn ?? '';
    if (!arn) return findings;

    // Prowler skips deleted CAs
    if (ca.Status === 'DELETED') return findings;

    const caId = arn.split('/').pop() ?? arn;
    const config: any = ca.CertificateAuthorityConfiguration ?? {};
    const keyAlgorithm: string = config.KeyAlgorithm ?? '';

    // acmpca_certificate_authority_pqc_key_algorithm: key algorithm must be ML-DSA
    if (!PQC_KEY_ALGORITHMS.includes(keyAlgorithm)) {
      findings.push(this.emit(
        'acmpca_certificate_authority_pqc_key_algorithm',
        {
          arn,
          certificateAuthorityId: caId,
          status: ca.Status ?? '',
          type: ca.Type ?? '',
          keyAlgorithm: keyAlgorithm || null,
          signingAlgorithm: config.SigningAlgorithm ?? null,
        },
        {
          message: `AWS Private CA "${caId}" uses key algorithm ${keyAlgorithm || '<none>'}, which is not post-quantum (ML-DSA)`,
          remediation: `Create a replacement Private CA for "${caId}" with an ML-DSA key algorithm (ML_DSA_44/ML_DSA_65/ML_DSA_87), re-issue certificates from it, and retire the legacy CA`,
        }
      ));
    }

    return findings;
  }
}

export default ACMPCAScanner;
