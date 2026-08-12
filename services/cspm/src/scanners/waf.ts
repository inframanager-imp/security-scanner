// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  ListWebACLsCommand,
  GetWebACLCommand,
  ListResourcesForWebACLCommand,
  GetLoggingConfigurationCommand,
  type WebACL,
} from '@aws-sdk/client-wafv2';
import {
  WAFClient,
  ListRulesCommand as ListClassicRulesCommand,
  GetRuleCommand as GetClassicRuleCommand,
  ListRuleGroupsCommand as ListClassicRuleGroupsCommand,
  ListActivatedRulesInRuleGroupCommand as ListClassicActivatedRulesCommand,
  ListWebACLsCommand as ListClassicWebACLsCommand,
  GetWebACLCommand as GetClassicWebACLCommand,
  GetLoggingConfigurationCommand as GetClassicLoggingConfigurationCommand,
} from '@aws-sdk/client-waf';
import {
  WAFRegionalClient,
  ListRulesCommand as ListRegionalRulesCommand,
  GetRuleCommand as GetRegionalRuleCommand,
  ListRuleGroupsCommand as ListRegionalRuleGroupsCommand,
  ListActivatedRulesInRuleGroupCommand as ListRegionalActivatedRulesCommand,
  ListWebACLsCommand as ListRegionalWebACLsCommand,
  GetWebACLCommand as GetRegionalWebACLCommand,
  GetLoggingConfigurationCommand as GetRegionalLoggingConfigurationCommand,
} from '@aws-sdk/client-waf-regional';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

type ClassicCommandCtor = new (input: any) => any;

/**
 * WAF Classic global and regional expose the same API shape through two SDK
 * packages, and Prowler's waf_global_* / waf_regional_* check pairs are
 * identical, so one table-driven pass covers both scopes.
 */
interface ClassicScopeDef {
  /** Human label used in finding messages */
  label: 'Global' | 'Regional';
  /** checkId prefix: waf_global | waf_regional */
  checkPrefix: 'waf_global' | 'waf_regional';
  /** ARN service component (classic global uses "waf", regional uses "waf-regional") */
  arnService: 'waf' | 'waf-regional';
  region: string;
  send: (command: any) => Promise<any>;
  commands: {
    listRules: ClassicCommandCtor;
    getRule: ClassicCommandCtor;
    listRuleGroups: ClassicCommandCtor;
    listActivatedRules: ClassicCommandCtor;
    listWebACLs: ClassicCommandCtor;
    getWebACL: ClassicCommandCtor;
    getLoggingConfiguration: ClassicCommandCtor;
  };
}

export class WAFScanner extends BaseScanner {
  private wafClassic: WAFClient;
  private wafRegional: WAFRegionalClient;

  constructor(client: AWSClient) {
    super(client, 'WAF');
    // WAF Classic global (CloudFront) API only exists in us-east-1 — pin like fms.ts
    this.wafClassic  = new WAFClient({ ...client.getClientConfig(), region: 'us-east-1' });
    this.wafRegional = new WAFRegionalClient(client.getClientConfig());
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
        findings.push(this.emit(
          'waf_webacls_configured',
          { resourceId: 'waf::no-acls', scope: 'REGIONAL' },
          {
            message: 'No AWS WAF WebACLs found in this region. Internet-facing resources (ALB, API Gateway, CloudFront) ' +
              'are not protected against common web exploits (OWASP Top 10), bots, and DDoS attacks.',
          }
        ));
      }
    }

    // ── WAF Classic (waf_global_* / waf_regional_* Prowler check families) ──
    const classicScopes: ClassicScopeDef[] = [
      {
        label: 'Regional',
        checkPrefix: 'waf_regional',
        arnService: 'waf-regional',
        region: this.client.getRegion(),
        send: (command: any) => this.wafRegional.send(command),
        commands: {
          listRules: ListRegionalRulesCommand,
          getRule: GetRegionalRuleCommand,
          listRuleGroups: ListRegionalRuleGroupsCommand,
          listActivatedRules: ListRegionalActivatedRulesCommand,
          listWebACLs: ListRegionalWebACLsCommand,
          getWebACL: GetRegionalWebACLCommand,
          getLoggingConfiguration: GetRegionalLoggingConfigurationCommand,
        },
      },
    ];
    // Classic global WAF lives only in us-east-1 — same guard as the CLOUDFRONT scope above
    if (this.client.getRegion() === 'us-east-1') {
      classicScopes.push({
        label: 'Global',
        checkPrefix: 'waf_global',
        arnService: 'waf',
        region: 'us-east-1',
        send: (command: any) => this.wafClassic.send(command),
        commands: {
          listRules: ListClassicRulesCommand,
          getRule: GetClassicRuleCommand,
          listRuleGroups: ListClassicRuleGroupsCommand,
          listActivatedRules: ListClassicActivatedRulesCommand,
          listWebACLs: ListClassicWebACLsCommand,
          getWebACL: GetClassicWebACLCommand,
          getLoggingConfiguration: GetClassicLoggingConfigurationCommand,
        },
      });
    }

    let accountId = '';
    try {
      accountId = await this.client.getAccountId();
    } catch (err) {
      logger.debug('WAF Classic: unable to resolve account id for ARNs', { error: (err as Error).message });
    }

    for (const classicScope of classicScopes) {
      findings.push(...(await this.scanClassicScope(classicScope, accountId)));
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
          findings.push(this.emit(
            'waf_webacl_resource_associated',
            { resourceId: aclArn, aclName, aclArn, scope },
            {
              message: `WAF WebACL "${aclName}" (${scope}) exists but is not associated with any ALB, API Gateway stage, or CloudFront distribution. ` +
                `The WebACL provides no protection until associated.`,
            }
          ));
        }

        // 2. WAF logging disabled
        if (!hasLogging) {
          findings.push(this.emit(
            'wafv2_webacl_logging_enabled',
            { resourceId: `${aclArn}::logging`, aclName, aclArn, scope },
            {
              message: `WAF WebACL "${aclName}" (${scope}) does not have logging enabled. ` +
                `Without logging, blocked requests and attack patterns cannot be analyzed.`,
            }
          ));
        }

        // 3. No AWS Managed Rule Groups
        const rules       = acl.Rules ?? [];
        const hasManagedRules = rules.some(r => r.Statement?.ManagedRuleGroupStatement != null);
        if (!hasManagedRules) {
          findings.push(this.emit(
            'waf_webacl_managed_rule_groups_configured',
            { resourceId: `${aclArn}::managed-rules`, aclName, aclArn, scope, ruleCount: rules.length },
            {
              message: `WAF WebACL "${aclName}" has no AWS Managed Rule Groups configured. ` +
                `Managed rules provide protection against OWASP Top 10, known bad inputs, and IP reputation threats.`,
            }
          ));
        }

        // 4. No rate limiting rule
        const hasRateLimit = rules.some(r => r.Statement?.RateBasedStatement != null);
        if (!hasRateLimit) {
          findings.push(this.emit(
            'waf_webacl_rate_based_rule_configured',
            { resourceId: `${aclArn}::rate-limit`, aclName, aclArn, scope },
            {
              message: `WAF WebACL "${aclName}" has no rate-based rule. ` +
                `Without rate limiting, the protected resource is vulnerable to brute force and DDoS attacks.`,
              remediation: `Add a rate-based rule to "${aclName}" limiting requests per IP to an appropriate threshold (e.g. 2000 req/5min).`,
            }
          ));
        }

        // 5. No rules or rule groups at all (Firewall Manager rule groups count too)
        const fmRuleGroups = [
          ...(acl.PreProcessFirewallManagerRuleGroups ?? []),
          ...(acl.PostProcessFirewallManagerRuleGroups ?? []),
        ];
        if (rules.length === 0 && fmRuleGroups.length === 0) {
          findings.push(this.emit(
            'wafv2_webacl_with_rules',
            { resourceId: `${aclArn}::no-rules`, aclName, aclArn, scope },
            {
              message: `WAF WebACL "${aclName}" (${scope}) has no rules or rule groups attached. ` +
                `Traffic is governed solely by the default action, with no inspection at all.`,
            }
          ));
        }

        // 6. Rules/rule groups without CloudWatch metrics (rule-level visibility)
        const rulesWithoutMetrics = [...rules, ...fmRuleGroups]
          .filter(r => !r.VisibilityConfig?.CloudWatchMetricsEnabled)
          .map(r => r.Name ?? 'unknown');
        if (rulesWithoutMetrics.length > 0) {
          findings.push(this.emit(
            'wafv2_webacl_rule_logging_enabled',
            { resourceId: `${aclArn}::rule-metrics`, aclName, aclArn, scope, rulesWithoutMetrics },
            {
              message: `WAF WebACL "${aclName}" (${scope}) has rules or rule groups without CloudWatch metrics enabled: ` +
                `${rulesWithoutMetrics.join(', ')}. Rule evaluation activity is invisible, masking spikes, bypasses, and misconfigurations.`,
            }
          ));
        }

      } catch (err) {
        logger.debug(`WAF scan failed for ${aclSummary.Name}`, { error: (err as Error).message });
      }
    }
    return findings;
  }

  /** Paginated list helper for WAF Classic APIs (ListRules/ListRuleGroups/ListWebACLs). */
  private async listClassic(classicScope: ClassicScopeDef, Command: ClassicCommandCtor, resultKey: string): Promise<any[]> {
    const items: any[] = [];
    let nextMarker: string | undefined;
    do {
      const result: any = await retry(() => classicScope.send(new Command({ NextMarker: nextMarker, Limit: 100 })));
      items.push(...(result[resultKey] ?? []));
      nextMarker = result.NextMarker;
    } while (nextMarker);
    return items;
  }

  /** One pass over a WAF Classic scope covering all four waf_{global|regional}_* checks. */
  private async scanClassicScope(classicScope: ClassicScopeDef, accountId: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const { label, checkPrefix, arnService, region, commands } = classicScope;

    try {
      // waf_{global|regional}_rule_with_conditions — rules must have >= 1 predicate
      const rules = await this.listClassic(classicScope, commands.listRules, 'Rules');
      for (const rule of rules) {
        try {
          const result: any = await retry(() => classicScope.send(new commands.getRule({ RuleId: rule.RuleId })));
          if ((result.Rule?.Predicates ?? []).length === 0) {
            const ruleName = rule.Name ?? rule.RuleId;
            findings.push(this.emit(
              `${checkPrefix}_rule_with_conditions`,
              {
                resourceId: `arn:aws:${arnService}:${region}:${accountId}:rule/${rule.RuleId}`,
                ruleId: rule.RuleId,
                ruleName,
                region,
              },
              {
                message: `WAF Classic ${label} rule "${ruleName}" has no conditions, so it never matches any request and provides no filtering.`,
                remediation: `Add at least one condition (predicate) such as an IP match, SQLi, XSS, or size constraint to WAF Classic ${label} rule "${ruleName}", or delete the placeholder rule.`,
              }
            ));
          }
        } catch (err) {
          logger.debug(`WAF Classic ${label}: failed to get rule ${rule.RuleId}`, { error: (err as Error).message });
        }
      }

      // waf_{global|regional}_rulegroup_not_empty — rule groups must contain >= 1 activated rule
      const ruleGroups = await this.listClassic(classicScope, commands.listRuleGroups, 'RuleGroups');
      for (const group of ruleGroups) {
        try {
          const result: any = await retry(() => classicScope.send(new commands.listActivatedRules({ RuleGroupId: group.RuleGroupId })));
          if ((result.ActivatedRules ?? []).length === 0) {
            const groupName = group.Name ?? group.RuleGroupId;
            findings.push(this.emit(
              `${checkPrefix}_rulegroup_not_empty`,
              {
                resourceId: `arn:aws:${arnService}:${region}:${accountId}:rulegroup/${group.RuleGroupId}`,
                ruleGroupId: group.RuleGroupId,
                ruleGroupName: groupName,
                region,
              },
              {
                message: `WAF Classic ${label} rule group "${groupName}" contains no rules, so it performs no inspection while appearing to provide protection.`,
                remediation: `Add at least one rule to WAF Classic ${label} rule group "${groupName}", or delete the empty rule group.`,
              }
            ));
          }
        } catch (err) {
          logger.debug(`WAF Classic ${label}: failed to list activated rules for rule group ${group.RuleGroupId}`, { error: (err as Error).message });
        }
      }

      // waf_{global|regional}_webacl_with_rules + waf_{global|regional}_webacl_logging_enabled
      const acls = await this.listClassic(classicScope, commands.listWebACLs, 'WebACLs');
      for (const aclSummary of acls) {
        const aclName = aclSummary.Name ?? aclSummary.WebACLId;
        const aclArn  = `arn:aws:${arnService}:${region}:${accountId}:webacl/${aclSummary.WebACLId}`;

        try {
          const result: any = await retry(() => classicScope.send(new commands.getWebACL({ WebACLId: aclSummary.WebACLId })));
          if ((result.WebACL?.Rules ?? []).length === 0) {
            findings.push(this.emit(
              `${checkPrefix}_webacl_with_rules`,
              { resourceId: `${aclArn}::no-rules`, aclId: aclSummary.WebACLId, aclName, region },
              {
                message: `WAF Classic ${label} WebACL "${aclName}" has no rules or rule groups, so traffic is governed solely by its default action with no inspection.`,
                remediation: `Add at least one rule or rule group to WAF Classic ${label} WebACL "${aclName}", or migrate it to WAFv2 with AWS Managed Rules.`,
              }
            ));
          }
        } catch (err) {
          logger.debug(`WAF Classic ${label}: failed to get WebACL ${aclSummary.WebACLId}`, { error: (err as Error).message });
        }

        // No retry here: GetLoggingConfiguration throws WAFNonexistentItemException when
        // logging was never configured — that is the FAIL signal, not a transient fault.
        let loggingEnabled = false;
        try {
          const logging: any = await classicScope.send(new commands.getLoggingConfiguration({ ResourceArn: aclArn }));
          loggingEnabled = (logging.LoggingConfiguration?.LogDestinationConfigs ?? []).length > 0;
        } catch { /* no logging configuration */ }
        if (!loggingEnabled) {
          findings.push(this.emit(
            `${checkPrefix}_webacl_logging_enabled`,
            { resourceId: `${aclArn}::logging`, aclId: aclSummary.WebACLId, aclName, region },
            {
              message: `WAF Classic ${label} WebACL "${aclName}" does not have logging enabled. Blocked requests and attack patterns cannot be analyzed.`,
              remediation: `Enable logging on WAF Classic ${label} WebACL "${aclName}" with a Kinesis Data Firehose delivery stream named aws-waf-logs-*.`,
            }
          ));
        }
      }
    } catch (err) {
      // WAF Classic unavailable in this region/account or no permission — skip silently
      logger.debug(`WAF Classic ${label} scan skipped`, { error: (err as Error).message });
    }

    return findings;
  }
}

export default WAFScanner;
