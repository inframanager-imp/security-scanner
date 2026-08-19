import { CheckMetadata } from '../../types';

// Titles must stay byte-identical to the pre-registry hardcoded titles:
// the scan worker dedupes OPEN findings on service:title:fingerprint, so a
// reworded title would re-open every existing finding as "new".
export const elbChecks: CheckMetadata[] = [
  {
    checkId: 'elbv2_logging_enabled',
    provider: 'aws',
    service: 'elb',
    title: 'Load Balancer Access Logging Disabled',
    severity: 'HIGH',
    description: 'Checks that load balancers have access logs enabled. Access logs are required for security analysis, compliance (PCI 10.2), and incident response.',
    remediation: 'Enable access logs on the load balancer: aws elbv2 modify-load-balancer-attributes --load-balancer-arn <lb-arn> --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=<your-log-bucket>',
    tags: ['elb', 'logging'],
  },
  {
    checkId: 'elbv2_deletion_protection',
    provider: 'aws',
    service: 'elb',
    title: 'Load Balancer Deletion Protection Disabled',
    severity: 'MEDIUM',
    description: 'Checks that load balancers have deletion protection enabled to prevent accidental or malicious deletion of a production load balancer.',
    remediation: 'Enable deletion protection: aws elbv2 modify-load-balancer-attributes --load-balancer-arn <lb-arn> --attributes Key=deletion_protection.enabled,Value=true',
    tags: ['elb', 'availability'],
  },
  {
    checkId: 'elbv2_ssl_listeners',
    provider: 'aws',
    service: 'elb',
    title: 'Load Balancer HTTP Listener Without HTTPS Redirect',
    severity: 'HIGH',
    description: 'Checks that HTTP listeners on internet-facing load balancers redirect traffic to HTTPS so data in transit is encrypted.',
    remediation: 'Add a redirect action to the HTTP listener: aws elbv2 modify-listener --listener-arn <listener-arn> --default-actions Type=redirect,RedirectConfig=\'{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}\'',
    tags: ['elb', 'encryption', 'https'],
  },
  {
    checkId: 'elbv2_insecure_ssl_ciphers',
    provider: 'aws',
    service: 'elb',
    title: 'Load Balancer Uses Weak TLS Policy',
    severity: 'HIGH',
    description: 'Checks that HTTPS listeners do not use SSL policies that support weak ciphers or TLS versions below 1.2.',
    remediation: 'Update to a modern TLS policy: aws elbv2 modify-listener --listener-arn <listener-arn> --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06',
    tags: ['elb', 'tls', 'encryption'],
  },
  {
    checkId: 'elb_target_group_insecure_backend_protocol',
    provider: 'aws',
    service: 'elb',
    title: 'Target Group Uses Unencrypted Backend Protocol',
    severity: 'MEDIUM',
    description: 'Checks that target groups do not forward traffic to backends using unencrypted HTTP or TCP; such traffic between the load balancer and the targets is unencrypted even if the listener uses TLS.',
    remediation: 'Switch the target group to HTTPS (or TLS) and configure the targets to terminate TLS, then update via: aws elbv2 modify-target-group --target-group-arn <target-group-arn> --protocol HTTPS',
    tags: ['elb', 'encryption', 'backend-tls'],
  },
];
