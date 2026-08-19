import { CheckMetadata } from '../../types';

// Titles must stay byte-identical to the pre-registry hardcoded titles:
// the scan worker dedupes OPEN findings on service:title:fingerprint, so a
// reworded title would re-open every existing finding as "new".
export const cloudfrontChecks: CheckMetadata[] = [
  {
    checkId: 'cloudfront_distributions_https_enabled',
    provider: 'aws',
    service: 'cloudfront',
    title: 'CloudFront Distribution Allows HTTP Traffic',
    severity: 'HIGH',
    description: 'Checks that CloudFront distributions do not allow HTTP traffic (ViewerProtocolPolicy: allow-all) on any cache behavior, so data in transit between viewers and CloudFront is encrypted.',
    remediation: 'Set ViewerProtocolPolicy to "redirect-to-https" or "https-only" on all cache behaviors in CloudFront distribution settings.',
    tags: ['cloudfront', 'https', 'encryption'],
  },
  {
    checkId: 'cloudfront_distributions_using_waf',
    provider: 'aws',
    service: 'cloudfront',
    title: 'CloudFront Distribution Not Protected By WAF',
    severity: 'HIGH',
    description: 'Checks that CloudFront distributions have a WAF WebACL attached; without WAF protection the distribution is exposed to web attacks (OWASP Top 10, bots, DDoS).',
    remediation: 'Associate a WAF WebACL (in us-east-1) with the CloudFront distribution via the WAF console or CloudFront settings.',
    tags: ['cloudfront', 'waf'],
  },
  {
    checkId: 'cloudfront_distributions_logging_enabled',
    provider: 'aws',
    service: 'cloudfront',
    title: 'CloudFront Distribution Access Logging Disabled',
    severity: 'MEDIUM',
    description: 'Checks that CloudFront distributions have access logging enabled so malicious traffic patterns and geographic abuse can be analyzed.',
    remediation: 'Enable access logging in CloudFront distribution settings. Specify an S3 bucket as the logging destination.',
    tags: ['cloudfront', 'logging'],
  },
  {
    checkId: 'cloudfront_distributions_using_deprecated_ssl_protocols',
    provider: 'aws',
    service: 'cloudfront',
    title: 'CloudFront Distribution Uses Weak TLS Protocol',
    severity: 'HIGH',
    description: 'Checks that CloudFront distributions do not allow weak minimum TLS protocol versions (< TLSv1.2), which are vulnerable to known attacks (BEAST, POODLE).',
    remediation: 'Update minimum TLS protocol to TLSv1.2_2021 in CloudFront viewer certificate settings.',
    tags: ['cloudfront', 'tls', 'encryption'],
  },
  {
    checkId: 'cloudfront_distributions_custom_ssl_certificate',
    provider: 'aws',
    service: 'cloudfront',
    title: 'CloudFront Distribution Using Default SSL Certificate',
    severity: 'LOW',
    description: 'Checks that CloudFront distributions use a custom ACM certificate instead of the default CloudFront SSL certificate, so users are not served the generic *.cloudfront.net domain.',
    remediation: 'Request a certificate in ACM (us-east-1) and configure it on the CloudFront distribution with a custom domain.',
    tags: ['cloudfront', 'certificate'],
  },
];
