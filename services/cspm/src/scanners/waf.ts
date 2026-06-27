import {
  ListWebACLsCommand,
  GetWebACLCommand,
  ListResourcesForWebACLCommand,
  GetLoggingConfigurationCommand,
  type WebACL,
} from '@aws-sdk/client-wafv2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class WAFScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'WAF');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    logger.info('Starting WAF security scan...');

    // Scan both REGIONAL (ALB/API GW) and CLOUDFRONT (global, us-east-1 only) scopes
    const scopes: Array<'REGIONAL' | 'CLOUDFRONT'> = ['REGIONAL'];
    // CloudFront WAF is always in us-east-1; only scan if we're in that region
    if ((this.client as any).getRegion?.() === 'us-east-1') scopes.push('CLOUDFRONT');

    for (const scope of scopes) {
      findings.push(...(await this.scanScope(scope)));
    }

    // Check if WAF is not deployed at all
    if (findings.filter(f => f.title === 'No WAF WebACLs Configured').length === 0) {
      const allAcls = await this.listACLs('REGIONAL');
      if (allAcls.length === 0) {
        findings.push(this.createFinding(
          'No WAF WebACLs Configured',
          'No AWS WAF WebACLs found in this region. Internet-facing resources (ALB, API Gateway, CloudFront) ' +
          'are not protected against common web exploits (OWASP Top 10), bots, and DDoS attacks.',
          'HIGH',
          { resourceId: 'waf::no-acls', scope: 'REGIONAL' },
          'Create WAF WebACLs with AWS Managed Rules and associate them with internet-facing ALBs, API Gateway stages, and CloudFront distributions.',
          ['waf', 'security'],
        ));
      }
    }

    logger.info(`WAF scan complete. ${findings.length} findings.`);
    return findings;
  }

  private async listACLs(scope: 'REGIONAL' | 'CLOUDFRONT'): Promise<any[]> {
    const acls: any[] = [];
    let nextMarker: string | undefined;
    try {
      do {
        const result = await retry(() =>
          this.client.wafv2.send(new ListWebACLsCommand({ Scope: scope, NextMarker: nextMarker, Limit: 100 }))
        );
        acls.push(...(result.WebACLs ?? []));
        nextMarker = result.NextMarker;
      } while (nextMarker);
    } catch { /* no WAF or no permission */ }
    return acls;
  }

  private async scanScope(scope: 'REGIONAL' | 'CLOUDFRONT'): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const acls = await this.listACLs(scope);

    for (const aclSummary of acls) {
      try {
        const [aclResult, resourcesResult, loggingResult] = await Promise.allSettled([
          retry(() => this.client.wafv2.send(new GetWebACLCommand({ Name: aclSummary.Name, Scope: scope, Id: aclSummary.Id }))),
          retry(() => this.client.wafv2.send(new ListResourcesForWebACLCommand({ WebACLArn: aclSummary.ARN, ResourceType: undefined }))),
          retry(() => this.client.wafv2.send(new GetLoggingConfigurationCommand({ ResourceArn: aclSummary.ARN }))),
        ]);

        const acl: WebACL | null = aclResult.status === 'fulfilled' ? (aclResult.value.WebACL ?? null) : null;
        const resources = resourcesResult.status === 'fulfilled' ? (resourcesResult.value.ResourceArns ?? []) : [];
        const hasLogging = loggingResult.status === 'fulfilled';

        if (!acl) continue;

        const aclName = acl.Name ?? 'Unknown';
        const aclArn  = acl.ARN  ?? '';

        // 1. WAF not associated with any resource
        if (resources.length === 0) {
          findings.push(this.createFinding(
            'WAF WebACL Not Associated With Any Resource',
            `WAF WebACL "${aclName}" (${scope}) exists but is not associated with any ALB, API Gateway stage, or CloudFront distribution. ` +
            `The WebACL provides no protection until associated.`,
            'MEDIUM',
            { resourceId: aclArn, aclName, aclArn, scope },
            `Associate the WebACL with an internet-facing resource in the WAF console.`,
            ['waf', 'configuration'],
          ));
        }

        // 2. WAF logging disabled
        if (!hasLogging) {
          findings.push(this.createFinding(
            'WAF WebACL Logging Disabled',
            `WAF WebACL "${aclName}" (${scope}) does not have logging enabled. ` +
            `Without logging, blocked requests and attack patterns cannot be analyzed.`,
            'MEDIUM',
            { resourceId: `${aclArn}::logging`, aclName, aclArn, scope },
            `Enable WAF logging to CloudWatch Logs or S3 in the WAF console under Logging and metrics.`,
            ['waf', 'logging'],
          ));
        }

        // 3. No AWS Managed Rule Groups
        const rules       = acl.Rules ?? [];
        const hasManagedRules = rules.some(r => r.Statement?.ManagedRuleGroupStatement != null);
        if (!hasManagedRules) {
          findings.push(this.createFinding(
            'WAF WebACL Has No Managed Rule Groups',
            `WAF WebACL "${aclName}" has no AWS Managed Rule Groups configured. ` +
            `Managed rules provide protection against OWASP Top 10, known bad inputs, and IP reputation threats.`,
            'HIGH',
            { resourceId: `${aclArn}::managed-rules`, aclName, aclArn, scope, ruleCount: rules.length },
            `Add AWS Managed Rule Groups: AWSManagedRulesCommonRuleSet (OWASP), AWSManagedRulesKnownBadInputsRuleSet, ` +
            `and AWSManagedRulesAmazonIpReputationList to the WebACL.`,
            ['waf', 'rules'],
          ));
        }

        // 4. No rate limiting rule
        const hasRateLimit = rules.some(r => r.Statement?.RateBasedStatement != null);
        if (!hasRateLimit) {
          findings.push(this.createFinding(
            'WAF WebACL Has No Rate Limiting Rule',
            `WAF WebACL "${aclName}" has no rate-based rule. ` +
            `Without rate limiting, the protected resource is vulnerable to brute force and DDoS attacks.`,
            'MEDIUM',
            { resourceId: `${aclArn}::rate-limit`, aclName, aclArn, scope },
            `Add a rate-based rule to "${aclName}" limiting requests per IP to an appropriate threshold (e.g. 2000 req/5min).`,
            ['waf', 'rate-limiting'],
          ));
        }

      } catch (err) {
        logger.debug(`WAF scan failed for ${aclSummary.Name}`, { error: (err as Error).message });
      }
    }
    return findings;
  }
}

export default WAFScanner;
