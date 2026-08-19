import { CheckMetadata } from '../../types';

// Titles must stay byte-identical to the pre-registry hardcoded titles:
// the scan worker dedupes OPEN findings on service:title:fingerprint, so a
// reworded title would re-open every existing finding as "new".
export const acmChecks: CheckMetadata[] = [
  {
    checkId: 'acm_certificates_expiration_check',
    provider: 'aws',
    service: 'acm',
    title: 'ACM Certificate Expiring Within 7 Days',
    severity: 'CRITICAL',
    description: 'Checks for ACM certificates expiring within 7 days; if not renewed, services using the certificate will show TLS errors to users.',
    remediation: 'Renew the certificate immediately. ACM-managed certificates renew automatically if DNS/email validation is still valid. Verify domain validation records are in place.',
    tags: ['acm', 'certificate', 'expiry'],
  },
  {
    checkId: 'acm_certificate_expiration_30_days',
    provider: 'aws',
    service: 'acm',
    title: 'ACM Certificate Expiring Within 30 Days',
    severity: 'HIGH',
    description: 'Checks for ACM certificates expiring within 30 days to ensure auto-renewal is configured before expiry.',
    remediation: 'Verify that ACM auto-renewal is active (check domain validation status in ACM console). If using email validation, respond to renewal approval emails.',
    tags: ['acm', 'certificate', 'expiry'],
  },
  {
    checkId: 'acm_certificate_expired',
    provider: 'aws',
    service: 'acm',
    title: 'ACM Certificate Expired',
    severity: 'HIGH',
    description: 'Checks for ACM certificates that have already expired; expired certificates still in use cause services to serve an invalid TLS certificate.',
    remediation: 'Request a new certificate in ACM for the domain and update all resources using the expired certificate.',
    tags: ['acm', 'certificate', 'expiry'],
  },
  {
    checkId: 'acm_certificate_not_in_use',
    provider: 'aws',
    service: 'acm',
    title: 'ACM Certificate Issued But Not In Use',
    severity: 'LOW',
    description: 'Checks for issued ACM certificates not associated with any AWS resource (CloudFront, ALB, API Gateway); unused certificates waste cost and may indicate forgotten resources.',
    remediation: 'Either associate the certificate with a resource or delete it: aws acm delete-certificate --certificate-arn <certificate-arn>',
    tags: ['acm', 'certificate'],
  },
  {
    checkId: 'acm_certificate_validation_pending',
    provider: 'aws',
    service: 'acm',
    title: 'ACM Certificate Validation Pending',
    severity: 'MEDIUM',
    description: 'Checks for ACM certificates stuck in PENDING_VALIDATION state, where the domain validation record (DNS CNAME or email) has not been completed.',
    remediation: 'Complete domain validation by adding the required DNS CNAME record or responding to the validation email.',
    tags: ['acm', 'certificate'],
  },
];
