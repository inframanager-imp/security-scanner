// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  SESv2Client,
  ListEmailIdentitiesCommand,
  GetEmailIdentityCommand,
} from '@aws-sdk/client-sesv2';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

/** Condition keys that scope a statement to a specific account/org/source (port of Prowler's restrictive-condition logic). */
const RESTRICTIVE_CONDITION_KEYS = new Set([
  'aws:sourceaccount',
  'aws:sourcearn',
  'aws:sourceowner',
  'aws:sourcevpc',
  'aws:sourcevpce',
  'aws:principalaccount',
  'aws:principalarn',
  'aws:principalorgid',
  'aws:principalorgpaths',
  'aws:resourceaccount',
  'aws:sourceip',
  'aws:vpcsourceip',
]);

function hasPublicPrincipal(statement: any): boolean {
  const principal = statement?.Principal;
  if (principal === '*' || principal === 'arn:aws:iam::*:root') return true;
  if (principal && typeof principal === 'object') {
    for (const key of ['AWS', 'CanonicalUser']) {
      const value = principal[key];
      const values: any[] = Array.isArray(value) ? value : value !== undefined ? [value] : [];
      if (values.some((v) => v === '*' || v === 'arn:aws:iam::*:root')) return true;
    }
  }
  return false;
}

function hasRestrictiveCondition(statement: any): boolean {
  const condition = statement?.Condition;
  if (!condition || typeof condition !== 'object') return false;
  for (const operator of Object.keys(condition)) {
    const block = condition[operator];
    if (block && typeof block === 'object') {
      for (const key of Object.keys(block)) {
        if (RESTRICTIVE_CONDITION_KEYS.has(key.toLowerCase())) return true;
      }
    }
  }
  return false;
}

/** Simplified port of Prowler's is_policy_public (default args: cross-account allowed). */
function isPolicyPublic(policy: any): boolean {
  for (const statement of policy?.Statement ?? []) {
    if (statement?.Effect !== 'Allow') continue;
    if (hasPublicPrincipal(statement) && !hasRestrictiveCondition(statement)) return true;
  }
  return false;
}

export class SESScanner extends BaseScanner {
  private ses: SESv2Client;

  constructor(client: AWSClient) {
    super(client, 'SES');
    this.ses = new SESv2Client(client.getClientConfig());
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting SES security scan...');

      const identities = await this.listEmailIdentities();
      logger.info(`SES: scanning ${identities.length} email identity(ies)`);

      for (const identity of identities) {
        try {
          findings.push(...(await this.validateIdentity(identity)));
        } catch (error) {
          logger.debug(`Failed to scan SES identity ${identity.IdentityName}`, { error: (error as Error).message });
        }
      }

      logger.info(`SES scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('SES scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listEmailIdentities(): Promise<any[]> {
    const identities: any[] = [];
    let nextToken: string | undefined;
    do {
      const result = await retry(async () => {
        return await this.ses.send(new ListEmailIdentitiesCommand({ NextToken: nextToken }));
      });
      identities.push(...(result.EmailIdentities ?? []));
      nextToken = result.NextToken;
    } while (nextToken);
    return identities;
  }

  private async validateIdentity(identitySummary: any): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const name: string = identitySummary.IdentityName ?? '';
    if (!name) return findings;

    const result = await retry(async () => {
      return await this.ses.send(new GetEmailIdentityCommand({ EmailIdentity: name }));
    });

    // ses_identity_dkim_enabled: DKIM must be verified (SUCCESS) with signing enabled
    const dkim: any = result.DkimAttributes ?? {};
    const dkimStatus: string | undefined = dkim.Status;
    const signingEnabled: boolean = dkim.SigningEnabled ?? false;
    if (!(dkimStatus === 'SUCCESS' && signingEnabled)) {
      let message: string;
      if (dkimStatus === 'PENDING' || dkimStatus === 'NOT_STARTED' || dkimStatus === 'TEMPORARY_FAILURE') {
        message = `SES identity "${name}" has DKIM signing not verified (status: ${dkimStatus})`;
      } else if (dkimStatus === 'FAILED') {
        message = `SES identity "${name}" has DKIM signing that failed verification`;
      } else if (dkimStatus === 'SUCCESS' && !signingEnabled) {
        message = `SES identity "${name}" has DKIM verified but signing is disabled`;
      } else {
        message = `SES identity "${name}" does not have DKIM signing configured`;
      }
      findings.push(this.emit(
        'ses_identity_dkim_enabled',
        {
          resourceId: name,
          identity: name,
          identityType: identitySummary.IdentityType,
          dkimStatus: dkimStatus ?? null,
          dkimSigningEnabled: signingEnabled,
        },
        { message }
      ));
    }

    // ses_identity_not_publicly_accessible: authorization policies must not be public
    const policies: Record<string, string> = result.Policies ?? {};
    const publicPolicyNames: string[] = [];
    for (const [policyName, policyDocument] of Object.entries(policies)) {
      try {
        const policy = JSON.parse(policyDocument);
        if (isPolicyPublic(policy)) {
          publicPolicyNames.push(policyName);
        }
      } catch (error) {
        logger.debug(`Failed to parse SES identity policy ${policyName} for ${name}`, { error: (error as Error).message });
      }
    }
    if (publicPolicyNames.length > 0) {
      findings.push(this.emit(
        'ses_identity_not_publicly_accessible',
        { resourceId: name, identity: name, publicPolicies: publicPolicyNames },
        {
          message: `SES identity "${name}" is publicly accessible due to its resource policy (${publicPolicyNames.join(', ')})`,
          remediation: `Restrict the authorization policy(ies) ${publicPolicyNames.join(', ')} on identity "${name}" to specific trusted principals or add restrictive conditions`,
        }
      ));
    }

    return findings;
  }
}

export default SESScanner;
