// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  OrganizationsClient,
  DescribeOrganizationCommand,
  ListPoliciesCommand,
  DescribePolicyCommand,
  ListTargetsForPolicyCommand,
  ListDelegatedAdministratorsCommand,
} from '@aws-sdk/client-organizations';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

export class OrganizationsScanner extends BaseScanner {
  private organizations: OrganizationsClient;

  constructor(client: AWSClient) {
    super(client, 'Organizations');
    this.organizations = new OrganizationsClient(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Organizations security scan...');

      let organization: any;
      try {
        const result = await retry(async () => {
          return await this.organizations.send(new DescribeOrganizationCommand({}));
        });
        organization = result.Organization;
      } catch (error) {
        const err = error as any;
        if (err?.name === 'AWSOrganizationsNotInUseException') {
          // organizations_account_part_of_organizations: account is not in an organization
          findings.push(this.emit(
            'organizations_account_part_of_organizations',
            { organizationStatus: 'NOT_AVAILABLE' },
            { message: 'AWS Organizations is not in use for this AWS account' }
          ));
          logger.info(`Organizations scan complete. Found ${findings.length} findings.`);
          return findings;
        }
        // AccessDenied or other failure: cannot determine organization state, emit nothing
        logger.debug('Unable to describe AWS Organization', { error: (error as Error).message });
        return findings;
      }

      if (!organization?.Id) {
        logger.debug('DescribeOrganization returned no organization; skipping Organizations checks');
        return findings;
      }
      const orgId: string = organization.Id;

      findings.push(...await this.checkDelegatedAdministrators(orgId));
      findings.push(...await this.checkPolicies(orgId));

      logger.info(`Organizations scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Organizations scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async checkDelegatedAdministrators(orgId: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    const admins: any[] = [];
    try {
      let nextToken: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.organizations.send(new ListDelegatedAdministratorsCommand({ NextToken: nextToken }));
        });
        admins.push(...(result.DelegatedAdministrators ?? []));
        nextToken = result.NextToken;
      } while (nextToken);
    } catch (error) {
      // AccessDenied for non-management accounts: cannot determine, emit nothing
      logger.debug('Unable to list Organizations delegated administrators', { error: (error as Error).message });
      return findings;
    }

    // No trusted-delegated-administrator allowlist is configured, so every delegated
    // administrator is reported for review (mirrors Prowler's default empty allowlist).
    if (admins.length > 0) {
      const adminIds = admins.map((a) => a.Id).filter(Boolean);
      findings.push(this.emit(
        'organizations_delegated_administrators',
        { organizationId: orgId, delegatedAdministrators: adminIds },
        {
          message: `AWS Organization ${orgId} has delegated administrator account(s) not on a trusted allowlist: ${adminIds.join(', ')}`,
        }
      ));
    }

    return findings;
  }

  private async checkPolicies(orgId: string): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    let scpPolicies: any[];
    let tagPolicies: any[];
    let aiOptOutPolicies: any[];
    try {
      scpPolicies = await this.listPolicies('SERVICE_CONTROL_POLICY');
      tagPolicies = await this.listPolicies('TAG_POLICY');
      aiOptOutPolicies = await this.listPolicies('AISERVICES_OPT_OUT_POLICY');
    } catch (error) {
      // AccessDenied for non-management accounts: cannot evaluate policy checks, emit nothing
      logger.debug('Unable to list Organizations policies', { error: (error as Error).message });
      return findings;
    }

    findings.push(...await this.checkAiOptOutPolicy(orgId, aiOptOutPolicies));
    findings.push(...await this.checkScpDenyRegions(orgId, scpPolicies));
    findings.push(...await this.checkTagPolicies(orgId, tagPolicies));

    return findings;
  }

  private async listPolicies(filter: string): Promise<any[]> {
    const policies: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.organizations.send(new ListPoliciesCommand({ Filter: filter as any, NextToken: nextToken }));
      });
      policies.push(...(result.Policies ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return policies;
  }

  private async describePolicyContent(policyId: string): Promise<any> {
    try {
      const result = await retry(async () => {
        return await this.organizations.send(new DescribePolicyCommand({ PolicyId: policyId }));
      });
      const content = result.Policy?.Content;
      return content ? JSON.parse(content) : {};
    } catch (error) {
      logger.debug(`Failed to describe Organizations policy ${policyId}`, { error: (error as Error).message });
      return {};
    }
  }

  private async checkAiOptOutPolicy(orgId: string, policies: any[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    // organizations_opt_out_ai_services_policy: an opt-out policy must opt out of all
    // AI services by default and block child accounts from overriding it
    if (policies.length === 0) {
      findings.push(this.emit(
        'organizations_opt_out_ai_services_policy',
        { organizationId: orgId, optOutPolicies: 0 },
        { message: `AWS Organization ${orgId} has no opt-out policy for AI services` }
      ));
      return findings;
    }

    let allConditionsPassed = false;
    let failureMessage = `AWS Organization ${orgId} has not opted out of all AI services`;
    for (const policy of policies) {
      const content = await this.describePolicyContent(policy.Id);
      const optOutPolicy = content?.services?.default?.opt_out_policy ?? {};
      const optedOut = optOutPolicy['@@assign'] === 'optOut';
      const operators = optOutPolicy['@@operators_allowed_for_child_policies'];
      const childOverrideBlocked = Array.isArray(operators) && operators.length === 1 && operators[0] === '@@none';

      if (optedOut && childOverrideBlocked) {
        allConditionsPassed = true;
        break;
      }
      if (!optedOut && !childOverrideBlocked) {
        failureMessage = `AWS Organization ${orgId} has not opted out of all AI services and does not disallow child accounts from overriding the policy`;
      } else if (!optedOut) {
        failureMessage = `AWS Organization ${orgId} has not opted out of all AI services`;
      } else {
        failureMessage = `AWS Organization ${orgId} has opted out of all AI services but does not disallow child accounts from overriding the policy`;
      }
    }

    if (!allConditionsPassed) {
      findings.push(this.emit(
        'organizations_opt_out_ai_services_policy',
        { organizationId: orgId, optOutPolicies: policies.length, compliantPolicy: false },
        { message: failureMessage }
      ));
    }

    return findings;
  }

  private async checkScpDenyRegions(orgId: string, policies: any[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    // organizations_scp_check_deny_regions: at least one SCP statement must restrict
    // activity by aws:RequestedRegion
    if (policies.length === 0) {
      findings.push(this.emit(
        'organizations_scp_check_deny_regions',
        { organizationId: orgId, scpPolicies: 0 },
        { message: `AWS Organization ${orgId} does not have SCP policies` }
      ));
      return findings;
    }

    // No approved-region list is configured, so any statement conditioning on
    // aws:RequestedRegion counts as a region restriction (matches Prowler's behavior
    // with an empty organizations_enabled_regions configuration).
    for (const policy of policies) {
      const content = await this.describePolicyContent(policy.Id);
      let statements: any[] = content?.Statement ?? [];
      if (!Array.isArray(statements)) statements = [statements];
      for (const statement of statements) {
        const denyRestricted = statement?.Effect === 'Deny'
          && statement?.Condition?.StringNotEquals?.['aws:RequestedRegion'] !== undefined;
        const allowRestricted = statement?.Effect === 'Allow'
          && statement?.Condition?.StringEquals?.['aws:RequestedRegion'] !== undefined;
        if (denyRestricted || allowRestricted) {
          // Region-restricting SCP found — check passes
          return findings;
        }
      }
    }

    findings.push(this.emit(
      'organizations_scp_check_deny_regions',
      { organizationId: orgId, scpPolicies: policies.length, regionRestrictingStatements: 0 },
      { message: `AWS Organization ${orgId} has SCP policies but none restrict AWS Regions` }
    ));

    return findings;
  }

  private async checkTagPolicies(orgId: string, policies: any[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    // organizations_tags_policies_enabled_and_attached: tag policies must exist and be
    // attached to at least one target
    if (policies.length === 0) {
      findings.push(this.emit(
        'organizations_tags_policies_enabled_and_attached',
        { organizationId: orgId, tagPolicies: 0 },
        { message: `AWS Organization ${orgId} does not have tag policies` }
      ));
      return findings;
    }

    for (const policy of policies) {
      try {
        const result = await retry(async () => {
          return await this.organizations.send(new ListTargetsForPolicyCommand({ PolicyId: policy.Id }));
        });
        if ((result.Targets ?? []).length > 0) {
          // Attached tag policy found — check passes
          return findings;
        }
      } catch (error) {
        logger.debug(`Failed to list targets for Organizations policy ${policy.Id}`, { error: (error as Error).message });
      }
    }

    findings.push(this.emit(
      'organizations_tags_policies_enabled_and_attached',
      { organizationId: orgId, tagPolicies: policies.length, attachedTagPolicies: 0 },
      { message: `AWS Organization ${orgId} has tag policies enabled but none are attached to a target` }
    ));

    return findings;
  }
}

export default OrganizationsScanner;
