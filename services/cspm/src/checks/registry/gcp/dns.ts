// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const dnsChecks: CheckMetadata[] = [
  {
    checkId: 'dns_dnssec_disabled',
    provider: 'gcp',
    service: 'dns',
    title: 'Cloud DNS Managed Zone Has DNSSEC Enabled',
    severity: 'MEDIUM',
    description: 'Checks that each Cloud DNS managed zone has DNSSEC enabled. Zones without DNSSEC publish unsigned, unauthenticated responses that are vulnerable to cache poisoning and spoofed referrals.',
    remediation: 'Enable DNSSEC on the managed zone (gcloud dns managed-zones update <ZONE> --dnssec-state on) and complete the chain of trust by publishing the resulting DS record at your domain registrar.',
    tags: ['dns', 'encryption', 'dnssec'],
  },
  {
    checkId: 'dns_rsasha1_in_use_to_key_sign_in_dnssec',
    provider: 'gcp',
    service: 'dns',
    title: 'DNSSEC Key-Signing Key Does Not Use RSASHA1',
    severity: 'MEDIUM',
    description: 'Checks that the DNSSEC key-signing key (KSK) algorithm for each managed zone is not RSASHA1, which is weak against collision-based forgery and rejected by some modern validating resolvers.',
    remediation: 'Turn DNSSEC off and back on for the zone, then set the key-signing key algorithm to RSASHA256 or ECDSAP256SHA256 under the advanced DNSSEC options before re-enabling.',
    tags: ['dns', 'encryption', 'dnssec'],
  },
  {
    checkId: 'dns_rsasha1_in_use_to_zone_sign_in_dnssec',
    provider: 'gcp',
    service: 'dns',
    title: 'DNSSEC Zone-Signing Key Does Not Use RSASHA1',
    severity: 'MEDIUM',
    description: 'Checks that the DNSSEC zone-signing key (ZSK) algorithm for each managed zone is not RSASHA1, which weakens record integrity and can cause resolution failures against SHA-1-rejecting resolvers.',
    remediation: 'Turn DNSSEC off and back on for the zone, then set the zone-signing key algorithm to RSASHA256 or ECDSAP256SHA256 under the advanced DNSSEC options before re-enabling.',
    tags: ['dns', 'vulnerabilities', 'dnssec'],
  },
];
