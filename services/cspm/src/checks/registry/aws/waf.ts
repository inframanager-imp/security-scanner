import { CheckMetadata } from '../../types';

// Titles must stay byte-identical to the pre-registry hardcoded titles:
// the scan worker dedupes OPEN findings on service:title:fingerprint, so a
// reworded title would re-open every existing finding as "new".
export const wafChecks: CheckMetadata[] = [
  {
    checkId: 'waf_webacls_configured',
    provider: 'aws',
    service: 'waf',
    title: 'No WAF WebACLs Configured',
    severity: 'HIGH',
    description: 'Checks that AWS WAF WebACLs exist in the region; without them, internet-facing resources (ALB, API Gateway, CloudFront) are not protected against common web exploits (OWASP Top 10), bots, and DDoS attacks.',
    remediation: 'Create WAF WebACLs with AWS Managed Rules and associate them with internet-facing ALBs, API Gateway stages, and CloudFront distributions.',
    tags: ['waf', 'security'],
  },
  {
    checkId: 'waf_webacl_resource_associated',
    provider: 'aws',
    service: 'waf',
    title: 'WAF WebACL Not Associated With Any Resource',
    severity: 'MEDIUM',
    description: 'Checks that WAF WebACLs are associated with at least one ALB, API Gateway stage, or CloudFront distribution; a WebACL provides no protection until associated.',
    remediation: 'Associate the WebACL with an internet-facing resource in the WAF console.',
    tags: ['waf', 'configuration'],
  },
  {
    checkId: 'wafv2_webacl_logging_enabled',
    provider: 'aws',
    service: 'waf',
    title: 'WAF WebACL Logging Disabled',
    severity: 'MEDIUM',
    description: 'Checks that WAF WebACLs have logging enabled so blocked requests and attack patterns can be analyzed.',
    remediation: 'Enable WAF logging to CloudWatch Logs or S3 in the WAF console under Logging and metrics.',
    tags: ['waf', 'logging'],
  },
  {
    checkId: 'waf_webacl_managed_rule_groups_configured',
    provider: 'aws',
    service: 'waf',
    title: 'WAF WebACL Has No Managed Rule Groups',
    severity: 'HIGH',
    description: 'Checks that WAF WebACLs include AWS Managed Rule Groups, which provide protection against OWASP Top 10, known bad inputs, and IP reputation threats.',
    remediation: 'Add AWS Managed Rule Groups: AWSManagedRulesCommonRuleSet (OWASP), AWSManagedRulesKnownBadInputsRuleSet, and AWSManagedRulesAmazonIpReputationList to the WebACL.',
    tags: ['waf', 'rules'],
  },
  {
    checkId: 'waf_webacl_rate_based_rule_configured',
    provider: 'aws',
    service: 'waf',
    title: 'WAF WebACL Has No Rate Limiting Rule',
    severity: 'MEDIUM',
    description: 'Checks that WAF WebACLs include a rate-based rule; without rate limiting, the protected resource is vulnerable to brute force and DDoS attacks.',
    remediation: 'Add a rate-based rule to the WebACL limiting requests per IP to an appropriate threshold (e.g. 2000 req/5min).',
    tags: ['waf', 'rate-limiting'],
  },
];
