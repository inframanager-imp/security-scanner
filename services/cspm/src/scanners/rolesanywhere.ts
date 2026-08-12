// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  RolesAnywhereClient,
  ListTrustAnchorsCommand,
} from '@aws-sdk/client-rolesanywhere';
import {
  ACMPCAClient,
  DescribeCertificateAuthorityCommand,
} from '@aws-sdk/client-acm-pca';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

// Prowler default allowlist of post-quantum (ML-DSA, NIST FIPS 204) key algorithms
const PQC_PCA_KEY_ALGORITHMS = ['ML_DSA_44', 'ML_DSA_65', 'ML_DSA_87'];

export class RolesAnywhereScanner extends BaseScanner {
  private rolesanywhere: RolesAnywhereClient;
  private acmpca: ACMPCAClient;

  constructor(client: AWSClient) {
    super(client, 'RolesAnywhere');
    this.rolesanywhere = new RolesAnywhereClient(client.getClientConfig());
    this.acmpca = new ACMPCAClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting RolesAnywhere security scan...');

      const trustAnchors = await this.listTrustAnchors();
      for (const anchor of trustAnchors) {
        try {
          const finding = await this.validateTrustAnchor(anchor);
          if (finding) findings.push(finding);
        } catch (error) {
          logger.debug(`Failed to scan RolesAnywhere trust anchor ${anchor.trustAnchorArn}`, { error: (error as Error).message });
        }
      }

      logger.info(`RolesAnywhere scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('RolesAnywhere scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listTrustAnchors(): Promise<any[]> {
    const anchors: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.rolesanywhere.send(new ListTrustAnchorsCommand({ nextToken }));
      });
      anchors.push(...(result.trustAnchors ?? []));
      nextToken = result.nextToken;
    } while (nextToken);
    return anchors;
  }

  // rolesanywhere_trust_anchor_pqc_pki: trust anchor must be backed by an
  // ACTIVE AWS Private CA using an ML-DSA key algorithm
  private async validateTrustAnchor(anchor: any): Promise<ScanningResult | null> {
    const name: string = anchor.name ?? anchor.trustAnchorId ?? '';
    const arn: string = anchor.trustAnchorArn ?? '';
    const source: any = anchor.source ?? {};
    const sourceType: string = source.sourceType ?? '';

    if (sourceType !== 'AWS_ACM_PCA') {
      // External certificate bundles cannot be inspected via the API — FAIL per Prowler
      return this.emit(
        'rolesanywhere_trust_anchor_pqc_pki',
        { trustAnchor: name, arn, sourceType: sourceType || '<none>' },
        {
          message: `Roles Anywhere trust anchor "${name}" uses source type ${sourceType || '<none>'}; its certificate signature algorithm cannot be inspected automatically. Migrate to an AWS Private CA using an ML-DSA key algorithm`,
        }
      );
    }

    const acmPcaArn: string = source.sourceData?.acmPcaArn ?? '';
    let ca: any;
    try {
      const result = await retry(async () => {
        return await this.acmpca.send(new DescribeCertificateAuthorityCommand({ CertificateAuthorityArn: acmPcaArn }));
      });
      ca = result.CertificateAuthority;
    } catch (error) {
      logger.debug(`RolesAnywhere: could not describe Private CA ${acmPcaArn}`, { error: (error as Error).message });
      ca = undefined;
    }

    if (!ca) {
      // Cross-account CA or missing acm-pca permissions — FAIL with guidance per Prowler
      return this.emit(
        'rolesanywhere_trust_anchor_pqc_pki',
        { trustAnchor: name, arn, acmPcaArn, inspected: false },
        {
          message: `Roles Anywhere trust anchor "${name}" is backed by Private CA ${acmPcaArn}, which could not be inspected (cross-account or missing acm-pca permissions). Verify the CA uses an ML-DSA key algorithm`,
        }
      );
    }

    const caId: string = (ca.Arn ?? acmPcaArn).split('/').pop() ?? acmPcaArn;
    const caStatus: string = ca.Status ?? '';
    const keyAlgorithm: string = ca.CertificateAuthorityConfiguration?.KeyAlgorithm ?? '';

    if (caStatus !== 'ACTIVE') {
      return this.emit(
        'rolesanywhere_trust_anchor_pqc_pki',
        { trustAnchor: name, arn, acmPcaArn, caStatus: caStatus || '<unknown>' },
        {
          message: `Roles Anywhere trust anchor "${name}" is backed by Private CA ${caId}, which is in ${caStatus || '<unknown>'} status and cannot be used as an active post-quantum PKI trust root`,
        }
      );
    }

    if (!PQC_PCA_KEY_ALGORITHMS.includes(keyAlgorithm)) {
      return this.emit(
        'rolesanywhere_trust_anchor_pqc_pki',
        { trustAnchor: name, arn, acmPcaArn, keyAlgorithm: keyAlgorithm || '<unknown>' },
        {
          message: `Roles Anywhere trust anchor "${name}" is backed by Private CA ${caId} using key algorithm ${keyAlgorithm || '<unknown>'}, which is not post-quantum (ML-DSA)`,
        }
      );
    }

    // PASS — CA is ACTIVE with an ML-DSA key algorithm
    return null;
  }
}

export default RolesAnywhereScanner;
