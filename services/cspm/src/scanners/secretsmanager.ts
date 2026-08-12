// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  ListSecretsCommand,
  DescribeSecretCommand,
  GetResourcePolicyCommand
} from '@aws-sdk/client-secrets-manager';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

const MAX_DAYS_SECRET_UNROTATED = 90;
const MAX_DAYS_SECRET_UNUSED = 90;
const DAY_MS = 24 * 60 * 60 * 1000;

// ─── IAM resource-policy helpers (ported from Prowler's IAM policy lib) ──────

const ARN_ROLE_USER_PATTERN = /^arn:aws:iam::\d{12}:(role|user)\/[^*]+$/;
const SERVICE_PRINCIPAL_PATTERN = /^[a-z0-9-]+(\.[a-z0-9-]+)*\.amazonaws\.com$/;
const IAM_ARN_WITH_ACCOUNT_PATTERN = /^arn:aws:iam::(\d{12}):/;
const ARN_ROLE_WILDCARD_PATTERN = /^arn:aws:iam::\d{12}:role\/.{12,}\*$/;

const RESTRICTIVE_CONDITION_KEYS = new Set([
  'aws:principalarn', 'aws:principalaccount', 'aws:principalorgid', 'aws:principalorgpaths',
  'aws:sourceaccount', 'aws:sourcearn', 'aws:sourceowner', 'aws:sourcevpc', 'aws:sourcevpce',
]);

/** Flatten a Principal-style field (string, array or {AWS, Service} map) into a string array. */
function extractField(field: any): string[] {
  if (typeof field === 'string') return [field];
  if (Array.isArray(field)) return field.filter((v: any) => typeof v === 'string');
  if (field && typeof field === 'object') {
    const result: string[] = [];
    for (const key of ['AWS', 'Service']) {
      const value = field[key];
      if (typeof value === 'string') result.push(value);
      else if (Array.isArray(value)) result.push(...value.filter((v: any) => typeof v === 'string'));
    }
    return result;
  }
  return [];
}

/** Normalize a scalar-or-array policy value (Action, Resource, condition values) into an array. */
function toArray(value: any): any[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function asStatements(policy: any): any[] {
  const raw = policy?.Statement;
  if (Array.isArray(raw)) return raw;
  return raw ? [raw] : [];
}

/** Lowercase condition keys inside each operator (IAM condition keys are case-insensitive). */
function normalizeConditionKeys(condition: any): any {
  const normalized: any = {};
  for (const [operator, keys] of Object.entries(condition)) {
    if (keys && typeof keys === 'object' && !Array.isArray(keys)) {
      const inner: any = {};
      for (const [key, value] of Object.entries(keys as Record<string, any>)) {
        inner[key.toLowerCase()] = value;
      }
      normalized[operator] = inner;
    } else {
      normalized[operator] = keys;
    }
  }
  return normalized;
}

/**
 * True when a condition block meaningfully restricts a wildcard principal:
 * an allow-list operator (StringEquals/StringLike/ArnEquals/ArnLike) scoping
 * access to our account, organization, or VPC.
 */
function isConditionRestrictive(condition: any, accountId: string | null): boolean {
  if (!condition || typeof condition !== 'object') return false;
  for (const [operator, block] of Object.entries(condition)) {
    const op = operator.toLowerCase();
    const isAllowListOperator =
      op.startsWith('stringequals') || op.startsWith('stringlike') ||
      op.startsWith('arnequals') || op.startsWith('arnlike');
    if (!isAllowListOperator || !block || typeof block !== 'object') continue;
    for (const [key, rawValues] of Object.entries(block as Record<string, any>)) {
      const keyLower = key.toLowerCase();
      if (!RESTRICTIVE_CONDITION_KEYS.has(keyLower)) continue;
      const values = toArray(rawValues).filter((v: any) => typeof v === 'string');
      if (values.length === 0 || values.includes('*')) continue;
      // Org/VPC-scoped keys restrict regardless of account; account/ARN keys must reference our account
      if (['aws:principalorgid', 'aws:principalorgpaths', 'aws:sourcevpc', 'aws:sourcevpce'].includes(keyLower)) {
        return true;
      }
      if (!accountId || values.some((v: string) => v.includes(accountId))) return true;
    }
  }
  return false;
}

/** A policy is public when an Allow statement has a wildcard principal without a restrictive condition. */
function isPolicyPublic(policy: any, accountId: string | null): boolean {
  for (const statement of asStatements(policy)) {
    if (statement?.Effect !== 'Allow') continue;
    if (!extractField(statement.Principal ?? {}).includes('*')) continue;
    if (!isConditionRestrictive(statement.Condition, accountId)) return true;
  }
  return false;
}

function setsEqual(a: Set<string>, b: Set<string>): boolean {
  if (a.size !== b.size) return false;
  for (const value of a) {
    if (!b.has(value)) return false;
  }
  return true;
}

/** Validate a service-principal Allow statement (explicit non-wildcard Action + aws:SourceAccount condition). */
function validateServiceAllowStatement(statement: any, accountId: string | null): string[] {
  const issues: string[] = [];
  if ('NotAction' in statement) issues.push('uses NotAction instead of Action');
  if ('NotResource' in statement) issues.push('uses NotResource instead of Resource');
  if (issues.length > 0) return issues;

  if (!('Action' in statement)) {
    issues.push('missing Action field');
  } else if (toArray(statement.Action).some((a: any) => typeof a === 'string' && a.includes('*'))) {
    issues.push('contains wildcard in Action field');
  }

  const condition = statement.Condition ?? {};
  const stringEquals = condition.StringEquals && typeof condition.StringEquals === 'object'
    ? condition.StringEquals
    : {};
  const sourceAccounts = toArray(stringEquals['aws:sourceaccount']).filter((v: any) => typeof v === 'string');
  const hasCorrectCondition = accountId
    ? sourceAccounts.includes(accountId)
    : sourceAccounts.length > 0;
  if (!hasCorrectCondition) {
    issues.push(Object.keys(condition).length === 0
      ? 'missing Condition block'
      : 'missing StringEquals condition on aws:SourceAccount for this account');
  }
  return issues;
}

/**
 * Port of Prowler's secretsmanager_has_restrictive_resource_policy evaluation.
 * Returns the list of failed restrictions (empty array means the policy is
 * sufficiently restrictive). The PrincipalOrgID deny layer is only enforced by
 * Prowler when organizations_trusted_ids is configured, which we do not have,
 * so that layer is treated as satisfied.
 */
function evaluateRestrictivePolicy(policy: any, accountId: string | null, secretArn: string | null): string[] {
  const failures: string[] = [];
  const statements = asStatements(policy).map(s =>
    s && s.Condition ? { ...s, Condition: normalizeConditionKeys(s.Condition) } : s
  );

  const isValidResource = (resource: any): boolean => {
    if (resource === undefined || resource === '*') return true;
    const resources = toArray(resource);
    if (resources.includes('*')) return true;
    return secretArn !== null && resources.length > 0 && resources.every((r: any) => r === secretArn);
  };

  // Pass 1 — detect cross-account access via Allow statements
  const crossAccountPrincipals: string[] = [];
  for (const statement of statements) {
    if (statement?.Effect !== 'Allow') continue;
    for (const principal of extractField(statement.Principal ?? {})) {
      const accountMatch = principal.match(IAM_ARN_WITH_ACCOUNT_PATTERN);
      if (accountMatch) {
        if (accountId && accountMatch[1] !== accountId) crossAccountPrincipals.push(principal);
      } else if (principal === '*') {
        if (!isConditionRestrictive(statement.Condition, accountId)) crossAccountPrincipals.push(principal);
      }
    }
  }

  // Pass 2 — look for an explicit deny-by-default statement for all principals
  const notDeniedPrincipals: string[] = [];
  const notDeniedServices: string[] = [];
  const arnNotLikePrincipals: string[] = [];
  let hasExplicitDenyForAll = false;

  const collectValidPrincipals = (values: any, pattern: RegExp, sink: string[]): boolean => {
    for (const entry of toArray(values)) {
      if (typeof entry === 'string' && pattern.test(entry)) sink.push(entry);
      else return false;
    }
    return true;
  };

  for (const statement of statements) {
    if (statement?.Effect !== 'Deny') continue;
    if (!extractField(statement.Principal ?? {}).includes('*')) continue;
    const actions = toArray(statement.Action);
    if (!actions.some((a: any) => a === '*' || a === 'secretsmanager:*')) continue;
    if (!isValidResource(statement.Resource)) continue;

    const condition = statement.Condition ?? {};
    let conditionPrincipals: any = {};
    if (condition.StringNotEquals && typeof condition.StringNotEquals === 'object') {
      conditionPrincipals = condition.StringNotEquals;
    } else if (condition.StringNotEqualsIfExists && typeof condition.StringNotEqualsIfExists === 'object') {
      conditionPrincipals = condition.StringNotEqualsIfExists;
    }

    const usesPrincipalArn = 'aws:principalarn' in conditionPrincipals;
    const usesPrincipalService = 'aws:principalservicename' in conditionPrincipals;

    const arnNotLikeCondition = condition.ArnNotLike && typeof condition.ArnNotLike === 'object'
      ? condition.ArnNotLike
      : {};
    const usesArnNotLike = 'aws:principalarn' in arnNotLikeCondition;

    const validKeys = new Set(['aws:principalarn', 'aws:principalservicename']);
    if (!Object.keys(conditionPrincipals).every(k => validKeys.has(k))) continue;

    let allValid = true;
    if (usesPrincipalArn) {
      allValid = collectValidPrincipals(conditionPrincipals['aws:principalarn'], ARN_ROLE_USER_PATTERN, notDeniedPrincipals);
    }
    if (allValid && usesPrincipalService) {
      allValid = collectValidPrincipals(conditionPrincipals['aws:principalservicename'], SERVICE_PRINCIPAL_PATTERN, notDeniedServices);
    }
    if (!allValid) continue;

    if (usesArnNotLike) {
      let arnsValid = true;
      for (const arn of toArray(arnNotLikeCondition['aws:principalarn'])) {
        if (typeof arn !== 'string' || !ARN_ROLE_WILDCARD_PATTERN.test(arn)) {
          arnsValid = false;
          break;
        }
        arnNotLikePrincipals.push(arn);
      }
      if (!arnsValid) continue;
    }

    // Strict operator-set validation so no additional operators can weaken the deny
    const operators = new Set(Object.keys(condition));
    if (usesPrincipalArn && usesPrincipalService) {
      const allowed = new Set(['StringNotEqualsIfExists', 'Null']);
      if (usesArnNotLike) allowed.add('ArnNotLike');
      if (setsEqual(operators, allowed)) {
        const nullCondition = condition.Null && typeof condition.Null === 'object' ? condition.Null : {};
        if (
          Object.keys(nullCondition).length === 2 &&
          nullCondition['aws:principalarn'] === 'true' &&
          nullCondition['aws:principalservicename'] === 'true'
        ) {
          hasExplicitDenyForAll = true;
          break;
        }
      }
    } else if (usesPrincipalArn) {
      const allowed = new Set(['StringNotEquals']);
      if (usesArnNotLike) allowed.add('ArnNotLike');
      if (setsEqual(operators, allowed)) {
        hasExplicitDenyForAll = true;
        break;
      }
    }
  }

  // Wildcard ArnNotLike principals must be validated by a Deny/ArnLike statement covering them all
  let hasArnLikeValidation = true;
  if (arnNotLikePrincipals.length > 0) {
    hasArnLikeValidation = false;
    const arnLikeValues: string[] = [];
    for (const statement of statements) {
      if (statement?.Effect !== 'Deny') continue;
      const arnLikeCondition = statement.Condition?.ArnLike;
      if (!arnLikeCondition || typeof arnLikeCondition !== 'object') continue;
      const values = toArray(arnLikeCondition['aws:principalarn']).filter((v: any) => typeof v === 'string');
      if (values.length === 0) continue;
      arnLikeValues.push(...values);
      if (setsEqual(new Set(arnNotLikePrincipals), new Set(arnLikeValues))) {
        hasArnLikeValidation = true;
        break;
      }
    }
  }

  // Per-principal NotAction hardening — only validated when a Deny statement names the principal
  const failedPrincipals: string[] = [];
  for (const statement of statements) {
    if (statement?.Effect !== 'Deny') continue;
    for (const principal of extractField(statement.Principal ?? {})) {
      if (!notDeniedPrincipals.includes(principal)) continue;
      const notActions = toArray(statement.NotAction);
      if (statement.NotAction === undefined || notActions.some((a: any) => typeof a === 'string' && a.includes('*'))) {
        failedPrincipals.push(principal);
      }
    }
  }

  // Service-principal Allow statements must be tightly scoped
  const failedServices: string[] = [];
  for (const statement of statements) {
    if (statement?.Effect !== 'Allow') continue;
    for (const service of extractField(statement.Principal ?? {})) {
      if (!notDeniedServices.includes(service)) continue;
      const issues = validateServiceAllowStatement(statement, accountId);
      if (issues.length > 0) failedServices.push(`${service} (${issues.join(', ')})`);
    }
  }

  if (crossAccountPrincipals.length > 0) {
    failures.push(
      `cross-account access is allowed for principal(s) ${crossAccountPrincipals.slice(0, 3).join(', ')}` +
      `${crossAccountPrincipals.length > 3 ? ' and more' : ''}`
    );
  }
  if (!hasExplicitDenyForAll) {
    failures.push('missing or incorrect Deny statement for all principals (expected StringNotEquals/StringNotEqualsIfExists on aws:PrincipalArn listing only authorized IAM roles or users)');
  }
  if (failedPrincipals.length > 0) {
    failures.push(`Deny statement for principal(s) ${[...new Set(failedPrincipals)].join(', ')} is missing a wildcard-free NotAction`);
  }
  if (failedServices.length > 0) {
    failures.push(`overly broad Allow statement(s) for service principal(s): ${failedServices.slice(0, 3).join('; ')}`);
  }
  if (!hasArnLikeValidation) {
    failures.push(`wildcard principal(s) ${arnNotLikePrincipals.join(', ')} in ArnNotLike lack a matching Deny/ArnLike validation statement`);
  }

  return failures;
}

export class SecretsManagerScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'SecretsManager');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting Secrets Manager security scan...');

      let accountId: string | null = null;
      try {
        accountId = await this.client.getAccountId();
      } catch (error) {
        logger.debug('Failed to resolve account id for Secrets Manager policy checks', { error: (error as Error).message });
      }

      const secrets = await this.listSecrets();
      for (const secret of secrets) {
        const secretName = secret.Name || 'Unknown';
        logger.debug(`Scanning secret: ${secretName}`);

        const secretFindings = await this.validateSecret(secret, accountId);
        findings.push(...secretFindings);
      }

      logger.info(`Secrets Manager scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('Secrets Manager scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listSecrets(): Promise<any[]> {
    return retry(async () => {
      logger.debug('Fetching secrets...');
      const secrets: any[] = [];
      let token: string | undefined;

      do {
        const result = await this.client.secretsmanager.send(
          new ListSecretsCommand({ NextToken: token, MaxResults: 100 })
        );
        secrets.push(...(result.SecretList || []));
        token = result.NextToken;
      } while (token);

      return secrets;
    });
  }

  private async validateSecret(secret: any, accountId: string | null): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    const secretName = secret.Name || 'Unknown';

    try {
      const details = await retry(async () => {
        const cmd = new DescribeSecretCommand({ SecretId: secretName });
        return await this.client.secretsmanager.send(cmd);
      });

      // Check if secret is scheduled for deletion
      if (details.DeletedDate) {
        findings.push(this.emit(
          'secretsmanager_secret_scheduled_for_deletion',
          { secretName, deleteDate: details.DeletedDate },
          {
            message: `Secret "${secretName}" is scheduled for deletion`,
          }
        ));
      }

      // Check rotation
      if (!details.RotationEnabled) {
        findings.push(this.emit(
          'secretsmanager_automatic_rotation_enabled',
          { secretName, rotationEnabled: details.RotationEnabled },
          {
            message: `Secret "${secretName}" does not have rotation enabled`,
            remediation: `Enable automatic rotation for secret "${secretName}"`,
          }
        ));
      }

      // Check encryption
      if (!details.KmsKeyId) {
        findings.push(this.emit(
          'secretsmanager_secret_encrypted_with_cmk',
          { secretName, kmsKey: details.KmsKeyId },
          {
            message: `Secret "${secretName}" uses default encryption instead of KMS`,
            remediation: `Consider using a customer-managed KMS key for secret "${secretName}"`,
          }
        ));
      }

      // Check replication
      if (!details.ReplicationStatus || details.ReplicationStatus.length === 0) {
        findings.push(this.emit(
          'secretsmanager_secret_cross_region_replication',
          { secretName, replicated: details.ReplicationStatus?.length === 0 },
          {
            message: `Secret "${secretName}" is not replicated for disaster recovery`,
            remediation: `Replicate secret "${secretName}" to another region for disaster recovery`,
          }
        ));
      }

      // secretsmanager_secret_rotated_periodically
      const lastRotatedDate: Date | undefined = details.LastRotatedDate;
      if (!lastRotatedDate) {
        findings.push(this.emit(
          'secretsmanager_secret_rotated_periodically',
          { secretName, lastRotatedDate: null },
          {
            message: `Secret "${secretName}" has never been rotated`,
          }
        ));
      } else {
        const daysSinceLastRotation = Math.floor((Date.now() - lastRotatedDate.getTime()) / DAY_MS);
        if (daysSinceLastRotation > MAX_DAYS_SECRET_UNROTATED) {
          findings.push(this.emit(
            'secretsmanager_secret_rotated_periodically',
            { secretName, lastRotatedDate, daysSinceLastRotation },
            {
              message: `Secret "${secretName}" has not been rotated in ${daysSinceLastRotation} days, which is more than the maximum allowed of ${MAX_DAYS_SECRET_UNROTATED} days`,
            }
          ));
        }
      }

      // secretsmanager_secret_unused
      const lastAccessedDate: Date | undefined = details.LastAccessedDate;
      if (!lastAccessedDate) {
        findings.push(this.emit(
          'secretsmanager_secret_unused',
          { secretName, lastAccessedDate: null },
          {
            message: `Secret "${secretName}" has never been accessed`,
          }
        ));
      } else {
        const daysSinceLastAccess = Math.floor((Date.now() - lastAccessedDate.getTime()) / DAY_MS);
        if (daysSinceLastAccess > MAX_DAYS_SECRET_UNUSED) {
          findings.push(this.emit(
            'secretsmanager_secret_unused',
            { secretName, lastAccessedDate, daysSinceLastAccess },
            {
              message: `Secret "${secretName}" has not been accessed in ${daysSinceLastAccess} days; review whether it is still needed`,
            }
          ));
        }
      }

      // Resource-policy based checks
      findings.push(...(await this.validateResourcePolicy(secretName, details.ARN, accountId)));
    } catch (error) {
      logger.debug(`Failed to validate secret ${secretName}`, { error: (error as Error).message });
    }

    return findings;
  }

  // secretsmanager_not_publicly_accessible / secretsmanager_has_restrictive_resource_policy
  private async validateResourcePolicy(
    secretName: string,
    secretArn: string | undefined,
    accountId: string | null
  ): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    let policy: any = null;

    try {
      const result: any = await retry(async () => {
        return await this.client.secretsmanager.send(
          new GetResourcePolicyCommand({ SecretId: secretArn ?? secretName })
        );
      });
      if (result?.ResourcePolicy) {
        policy = JSON.parse(result.ResourcePolicy);
      }
    } catch (error) {
      // Cannot distinguish "restrictive" from "unreadable" without the policy — skip both checks
      logger.debug(`Failed to get resource policy for secret ${secretName}`, { error: (error as Error).message });
      return findings;
    }

    // secretsmanager_not_publicly_accessible — only evaluable when a policy exists
    if (policy && isPolicyPublic(policy, accountId)) {
      findings.push(this.emit(
        'secretsmanager_not_publicly_accessible',
        { secretName, arn: secretArn ?? null },
        {
          message: `Secret "${secretName}" is publicly accessible due to its resource policy`,
          remediation: `Remove wildcard principals from the resource policy of secret "${secretName}" and grant access only to specific IAM principals`,
        }
      ));
    }

    // secretsmanager_has_restrictive_resource_policy
    if (!policy) {
      findings.push(this.emit(
        'secretsmanager_has_restrictive_resource_policy',
        { secretName, arn: secretArn ?? null, policy: null },
        {
          message: `Secret "${secretName}" does not have a resource-based policy`,
          remediation: `Attach a deny-by-default resource policy to secret "${secretName}" with a Deny for Principal "*" using StringNotEquals on aws:PrincipalArn listing only authorized roles`,
        }
      ));
    } else {
      const failedRestrictions = evaluateRestrictivePolicy(policy, accountId, secretArn ?? null);
      if (failedRestrictions.length > 0) {
        findings.push(this.emit(
          'secretsmanager_has_restrictive_resource_policy',
          { secretName, arn: secretArn ?? null, failedRestrictions },
          {
            message: `Secret "${secretName}" does not meet all required policy restrictions: ${failedRestrictions.join('; ')}`,
          }
        ));
      }
    }

    return findings;
  }
}

export default SecretsManagerScanner;
