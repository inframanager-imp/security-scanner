// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  FMSClient,
  ListPoliciesCommand,
  ListComplianceStatusCommand,
} from '@aws-sdk/client-fms';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

/**
 * AWS Firewall Manager is a management-account (delegated administrator)
 * service; Prowler treats it as global. Member accounts get AccessDenied on
 * ListPolicies — that is expected and results in a silent skip.
 */
export class FMSScanner extends BaseScanner {
  private fms: FMSClient;

  constructor(client: AWSClient) {
    super(client, 'FMS');
    // Global service — pin us-east-1 to match Prowler's global-service client
    this.fms = new FMSClient({ ...client.getClientConfig(), region: 'us-east-1' });
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting FMS security scan...');

      let policies: any[];
      try {
        policies = await this.listPolicies();
      } catch (error) {
        const err = error as any;
        const name: string = err?.name ?? '';
        const message: string = err?.message ?? '';
        if (
          name.includes('AccessDenied') ||
          name === 'InvalidOperationException' ||
          message.includes('No default admin could be found for account') ||
          message.includes('only available to AWS Firewall Manager Administrators')
        ) {
          // Not the Firewall Manager administrator account — FMS not applicable here
          logger.debug('FMS: account is not a Firewall Manager administrator, skipping', { error: message });
          return findings;
        }
        throw error;
      }

      // fms_policy_compliant — admin account confirmed at this point
      if (policies.length === 0) {
        findings.push(this.emit(
          'fms_policy_compliant',
          { policies: 0 },
          {
            message: 'FMS is enabled in this administrator account but has no Firewall Manager policies, so member accounts have no centrally enforced protections',
          }
        ));
      } else {
        let nonCompliantFound = false;
        for (const policy of policies) {
          if (nonCompliantFound) break;
          try {
            const statuses = await this.listComplianceStatus(policy.PolicyId);
            for (const memberStatus of statuses) {
              const evaluationResults: any[] = memberStatus.EvaluationResults ?? [];
              const complianceStatus: string = evaluationResults.length > 0
                ? (evaluationResults[0].ComplianceStatus ?? '')
                : '';
              if (complianceStatus === 'NON_COMPLIANT' || !complianceStatus) {
                findings.push(this.emit(
                  'fms_policy_compliant',
                  {
                    policyId: policy.PolicyId,
                    policyName: policy.PolicyName,
                    policyArn: policy.PolicyArn,
                    securityServiceType: policy.SecurityServiceType,
                    memberAccount: memberStatus.MemberAccount,
                    complianceStatus: complianceStatus || 'UNKNOWN',
                  },
                  {
                    message: `FMS policy "${policy.PolicyName}" is non-compliant for account ${memberStatus.MemberAccount}`,
                    remediation: `Review FMS policy "${policy.PolicyName}", enable automatic remediation and resolve the non-compliant resources in account ${memberStatus.MemberAccount}`,
                  }
                ));
                nonCompliantFound = true;
                break;
              }
            }
          } catch (error) {
            logger.debug(`FMS: failed to list compliance status for policy ${policy.PolicyId}`, { error: (error as Error).message });
          }
        }
      }

      logger.info(`FMS scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('FMS scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listPolicies(): Promise<any[]> {
    const policies: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.fms.send(new ListPoliciesCommand({ NextToken: nextToken }));
      });
      policies.push(...(result.PolicyList ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return policies;
  }

  private async listComplianceStatus(policyId: string): Promise<any[]> {
    const statuses: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.fms.send(new ListComplianceStatusCommand({ PolicyId: policyId, NextToken: nextToken }));
      });
      statuses.push(...(result.PolicyComplianceStatusList ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return statuses;
  }
}

export default FMSScanner;
