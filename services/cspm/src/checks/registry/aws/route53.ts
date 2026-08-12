// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import { CheckMetadata } from '../../types';

export const route53Checks: CheckMetadata[] = [
  {
    checkId: 'route53_dangling_ip_subdomain_takeover',
    provider: 'aws',
    service: 'route53',
    title: 'Route53 Dangling Record Enables Subdomain Takeover',
    severity: 'HIGH',
    description: 'Checks Route53 records for subdomain takeover vectors: non-alias A records pointing to AWS public IPs not allocated to the account (released Elastic IPs or ENI addresses), and non-alias CNAME records targeting S3 website endpoints whose bucket no longer exists.',
    remediation: 'Remove or update any record pointing to an unowned AWS resource. Avoid hard-coding AWS public IPs in A records; prefer alias records to managed endpoints (ALB, CloudFront, S3) and delete CNAMEs as soon as the backing bucket is removed.',
    tags: ['route53', 'dns', 'subdomain-takeover'],
  },
  {
    checkId: 'route53_domains_transferlock_enabled',
    provider: 'aws',
    service: 'route53',
    title: 'Route53 Domain Transfer Lock Disabled',
    severity: 'HIGH',
    description: 'Checks that Route53 registered domains have the transfer lock (clientTransferProhibited status) enabled to prevent unauthorized registrar transfers.',
    remediation: 'Enable the transfer lock on the domain. For planned transfers, remove the lock only under approved change control and re-enable it immediately afterward.',
    tags: ['route53', 'domain', 'transfer-lock'],
  },
  {
    checkId: 'route53_domains_privacy_protection_enabled',
    provider: 'aws',
    service: 'route53',
    title: 'Route53 Domain WHOIS Privacy Disabled',
    severity: 'MEDIUM',
    description: 'Checks that Route53 registered domains have WHOIS privacy protection enabled so administrative contact details are redacted instead of publicly listed.',
    remediation: 'Enable WHOIS privacy protection for all domain contacts (admin, registrant, tech) and use dedicated, monitored contact emails.',
    tags: ['route53', 'domain', 'privacy'],
  },
  {
    checkId: 'route53_public_hosted_zones_cloudwatch_logging_enabled',
    provider: 'aws',
    service: 'route53',
    title: 'Route53 Query Logging Not Enabled',
    severity: 'MEDIUM',
    description: 'Checks that Route53 public hosted zones have DNS query logging enabled to CloudWatch Logs, recording resolver requests for the zone.',
    remediation: 'Enable query logging for each public hosted zone to a centralized CloudWatch Logs group, with retention, metric filters and alerting.',
    tags: ['route53', 'dns', 'logging', 'audit'],
  },
];
