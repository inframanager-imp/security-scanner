// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const rolesanywhereChecks: CheckMetadata[] = [
  {
    checkId: 'rolesanywhere_trust_anchor_pqc_pki',
    provider: 'aws',
    service: 'rolesanywhere',
    title: 'Roles Anywhere Trust Anchor Without Post-Quantum PKI',
    severity: 'LOW',
    description: 'Checks that IAM Roles Anywhere trust anchors are backed by an active AWS Private CA using a post-quantum ML-DSA key algorithm; anchors backed by RSA/ECC CAs, inactive CAs, or uninspectable certificate bundles are flagged.',
    remediation: 'Create an AWS Private CA with an ML-DSA key algorithm (ML_DSA_44/65/87), point a new trust anchor at it, rotate end-entity certificates from the new CA, then remove the legacy trust anchor.',
    tags: ['rolesanywhere', 'pki', 'post-quantum', 'encryption'],
  },
];
