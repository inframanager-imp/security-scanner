// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const acmpcaChecks: CheckMetadata[] = [
  {
    checkId: 'acmpca_certificate_authority_pqc_key_algorithm',
    provider: 'aws',
    service: 'acmpca',
    title: 'ACM Private CA Not Using Post-Quantum Key Algorithm',
    severity: 'LOW',
    description: 'Checks that each non-deleted AWS Private CA uses a post-quantum ML-DSA key algorithm (ML_DSA_44, ML_DSA_65 or ML_DSA_87); RSA and ECC signatures are breakable by a sufficiently large quantum computer.',
    remediation: 'Existing CAs cannot change key algorithm. Create a replacement Private CA with an ML-DSA key algorithm (e.g. ML_DSA_65), re-issue certificates from it, and decommission the legacy RSA/ECC CA once dependent workloads have rotated.',
    tags: ['acmpca', 'encryption', 'post-quantum', 'pki'],
  },
];
