// Check logic derived from Prowler (Apache-2.0, https://github.com/prowler-cloud/prowler)
import {
  ListKeysCommand,
  DescribeKeyCommand,
  GetKeyRotationStatusCommand,
  GetKeyPolicyCommand,
  ListResourceTagsCommand,
  ListAliasesCommand
} from '@aws-sdk/client-kms';
import { BaseScanner, ScannerOptions } from './baseScanner';
import AWSClient from '../aws/client';
import { ScanningResult } from '../utils/types';
import logger from '../utils/logger';
import { retry } from '../utils/helpers';

function toArray(value: any): any[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

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
  if (principal === '*') return true;
  if (principal && typeof principal === 'object') {
    for (const key of ['AWS', 'CanonicalUser']) {
      if (toArray(principal[key]).some((v: any) => v === '*' || v === 'arn:aws:iam::*:root')) return true;
    }
  }
  return false;
}

function hasRestrictiveCondition(statement: any): boolean {
  const condition = statement?.Condition;
  if (!condition || typeof condition !== 'object') return false;
  for (const block of Object.values(condition)) {
    if (!block || typeof block !== 'object') continue;
    for (const key of Object.keys(block)) {
      if (RESTRICTIVE_CONDITION_KEYS.has(key.toLowerCase())) return true;
    }
  }
  return false;
}

/** Simplified port of Prowler's is_policy_public for KMS key policies (any action counts). */
function isPolicyPublic(policy: any): boolean {
  for (const statement of toArray(policy?.Statement)) {
    if (!statement || typeof statement !== 'object' || statement.Effect !== 'Allow') continue;
    if (hasPublicPrincipal(statement) && !hasRestrictiveCondition(statement)) return true;
  }
  return false;
}

// ── Nitro Enclave attestation policy analysis (port of Prowler's kms/lib/enclave helpers) ──

const ATTESTATION_KEY_PREFIX = 'kms:recipientattestation:';

/** Sensitive KMS actions whose Allow statements must be attestation-bound on enclave keys. */
const SENSITIVE_KMS_ACTIONS = new Set([
  'kms:decrypt',
  'kms:derivesharedsecret',
  'kms:generatedatakey',
  'kms:generatedatakeypair',
  'kms:generaterandom',
  'kms:*',
  '*',
]);

const CONCRETE_SENSITIVE_KMS_ACTIONS = [
  'kms:decrypt',
  'kms:derivesharedsecret',
  'kms:generatedatakey',
  'kms:generatedatakeypair',
  'kms:generaterandom',
];

/** PCRs that bind a deployment context (parent role / instance / signing cert); PCR0/1/2 travel with the image. */
const DEPLOYMENT_BINDING_PCRS = ['pcr3', 'pcr4', 'pcr8'];

const ACCOUNT_BINDING_CONDITION_KEYS = new Set([
  'aws:principalaccount',
  'aws:sourceaccount',
  'aws:principalorgid',
  'aws:resourceaccount',
  'aws:principalorgpaths',
]);

const RESTRICTIVE_EQUALITY_OPERATORS = new Set(['stringequals', 'stringequalsignorecase', 'arnequals']);

function sensitiveActionsOf(statement: any): string[] {
  return toArray(statement?.Action)
    .map((action: any) => String(action))
    .filter((action: string) => SENSITIVE_KMS_ACTIONS.has(action.toLowerCase()));
}

function statementTargetsSensitiveActions(statement: any): boolean {
  return sensitiveActionsOf(statement).length > 0;
}

/**
 * Restrictive kms:RecipientAttestation:* condition keys carried by a statement.
 * ForAllValues:* operators pass vacuously when the request omits the key, so they
 * only count when paired with a Null:false guard on the same key; wildcard-only
 * values do not count as a binding.
 */
function attestationConditionKeys(statement: any): string[] {
  const condition = statement?.Condition;
  if (!condition || typeof condition !== 'object') return [];

  // Null:{key:false} asserts the attestation key must be present in the request.
  const nullFalseKeys = new Set<string>();
  for (const [operator, block] of Object.entries(condition)) {
    if (operator.toLowerCase() !== 'null' || !block || typeof block !== 'object') continue;
    for (const [key, raw] of Object.entries(block as Record<string, any>)) {
      if (!key.toLowerCase().startsWith(ATTESTATION_KEY_PREFIX)) continue;
      if (toArray(raw).some((v: any) => String(v).toLowerCase() === 'false')) nullFalseKeys.add(key);
    }
  }

  const keys: string[] = [];
  for (const [operator, block] of Object.entries(condition)) {
    const op = operator.toLowerCase();
    if (op === 'null' || !block || typeof block !== 'object') continue;
    for (const [key, raw] of Object.entries(block as Record<string, any>)) {
      if (!key.toLowerCase().startsWith(ATTESTATION_KEY_PREFIX)) continue;
      const values = toArray(raw).map((v: any) => String(v));
      if (values.length === 0) continue;
      if (values.every((v) => v === '*' || v === '')) continue;
      if (op.startsWith('forallvalues:') && !nullFalseKeys.has(key)) continue;
      if (!keys.includes(key)) keys.push(key);
    }
  }
  for (const key of nullFalseKeys) {
    if (!keys.includes(key)) keys.push(key);
  }
  return keys;
}

/** True when an attestation-bound statement also binds a deployment context (PCR3/PCR4/PCR8 or account/org condition). */
function statementBindsDeployment(statement: any): boolean {
  const attestationKeys = attestationConditionKeys(statement).map((key) => key.toLowerCase());
  if (attestationKeys.length === 0) return false;
  if (attestationKeys.some((key) => DEPLOYMENT_BINDING_PCRS.some((pcr) => key.endsWith(`:${pcr}`)))) return true;

  const condition = statement?.Condition;
  if (!condition || typeof condition !== 'object') return false;
  for (const [operator, block] of Object.entries(condition)) {
    let op = operator.toLowerCase();
    if (op.startsWith('foranyvalue:')) op = op.slice('foranyvalue:'.length);
    if (!RESTRICTIVE_EQUALITY_OPERATORS.has(op) || !block || typeof block !== 'object') continue;
    for (const [key, raw] of Object.entries(block as Record<string, any>)) {
      if (!ACCOUNT_BINDING_CONDITION_KEYS.has(key.toLowerCase())) continue;
      const values = toArray(raw).map((v: any) => String(v));
      if (values.length > 0 && values.every((v) => !v.includes('*'))) return true;
    }
  }
  return false;
}

/**
 * True when a Deny statement neutralizes an unattested Allow: it applies to every
 * principal, covers the Allow's sensitive actions, and either is unconditional or
 * fires when attestation is absent (Null:{kms:RecipientAttestation:*: true}).
 */
function statementIsCoveredByDeny(statement: any, statements: any[]): boolean {
  const allowActions = sensitiveActionsOf(statement).map((action) => action.toLowerCase());
  const effectiveActions = allowActions.some((action) => action === 'kms:*' || action === '*')
    ? CONCRETE_SENSITIVE_KMS_ACTIONS
    : allowActions;

  for (const deny of statements) {
    if (!deny || typeof deny !== 'object' || deny.Effect !== 'Deny') continue;
    if (deny.NotPrincipal !== undefined) continue; // NotPrincipal carve-outs are not evaluated
    const principal = deny.Principal;
    const appliesToEveryone =
      principal === '*' ||
      (principal && typeof principal === 'object' && toArray(principal.AWS).some((p: any) => p === '*'));
    if (!appliesToEveryone) continue;

    const denyActions = toArray(deny.Action).map((action: any) => String(action).toLowerCase());
    const coversActions = effectiveActions.every(
      (action) => denyActions.includes(action) || denyActions.includes('kms:*') || denyActions.includes('*')
    );
    if (!coversActions) continue;

    const condition = deny.Condition;
    if (!condition || typeof condition !== 'object') return true; // unconditional deny
    for (const [operator, block] of Object.entries(condition)) {
      if (operator.toLowerCase() !== 'null' || !block || typeof block !== 'object') continue;
      for (const [key, raw] of Object.entries(block as Record<string, any>)) {
        if (!key.toLowerCase().startsWith(ATTESTATION_KEY_PREFIX)) continue;
        if (toArray(raw).some((v: any) => String(v).toLowerCase() === 'true')) return true;
      }
    }
  }
  return false;
}

/**
 * A key backs Nitro Enclave workloads when tagged prowler:enclave-key=true, when
 * "enclave" appears in its description, tags or aliases, or when its policy
 * references kms:RecipientAttestation:* conditions.
 */
function isEnclaveKey(details: { description: string; tags: any[]; aliases: string[]; policy: any }): boolean {
  for (const tag of details.tags) {
    const tagKey = String(tag?.TagKey ?? '').toLowerCase();
    const tagValue = String(tag?.TagValue ?? '').toLowerCase();
    if (tagKey === 'prowler:enclave-key' && tagValue === 'true') return true;
    if (tagKey.includes('enclave') || tagValue.includes('enclave')) return true;
  }
  if (details.description.toLowerCase().includes('enclave')) return true;
  if (details.aliases.some((alias) => alias.toLowerCase().includes('enclave'))) return true;
  if (details.policy && /kms:recipientattestation:/i.test(JSON.stringify(details.policy))) return true;
  return false;
}

interface EnclavePolicyFailure {
  message: string;
  remediation: string;
  evidence: any;
}

interface EnclavePolicyContext {
  keyId: string;
  statements: any[];
}

/** Table-driven Nitro Enclave attestation policy checks: checkId → failure detector (null = key passes). */
const ENCLAVE_POLICY_CHECKS: {
  checkId: string;
  evaluate: (ctx: EnclavePolicyContext) => EnclavePolicyFailure | null;
}[] = [
  {
    // Every sensitive Allow must carry a kms:RecipientAttestation:* condition.
    checkId: 'kms_key_enclave_attestation_not_enforced',
    evaluate: ({ keyId, statements }) => {
      for (const statement of statements) {
        if (statement.Effect !== 'Allow' || !statementTargetsSensitiveActions(statement)) continue;
        if (attestationConditionKeys(statement).length === 0) {
          const actions = toArray(statement.Action).map((a: any) => String(a)).sort().join(', ');
          return {
            message: `KMS enclave key "${keyId}" allows sensitive action(s) ${actions || '<none>'} without any kms:RecipientAttestation:* condition`,
            remediation: `Add a kms:RecipientAttestation:* condition (e.g. PCR0 bound to the enclave image measurement) to every sensitive Allow statement in the key policy of "${keyId}"`,
            evidence: { sid: statement.Sid ?? null, actions },
          };
        }
      }
      return null;
    },
  },
  {
    // An unattested sensitive Allow is a bypass path unless a Deny fires when attestation is absent.
    checkId: 'kms_key_enclave_attestation_bypassable_path',
    evaluate: ({ keyId, statements }) => {
      for (const statement of statements) {
        if (statement.Effect !== 'Allow' || !statementTargetsSensitiveActions(statement)) continue;
        if (attestationConditionKeys(statement).length > 0) continue;
        if (statementIsCoveredByDeny(statement, statements)) continue;
        const sid = statement.Sid ?? '(no Sid)';
        return {
          message: `KMS enclave key "${keyId}" exposes a bypass path in statement '${sid}': sensitive actions are allowed without kms:RecipientAttestation:* and no Deny neutralizes the gap`,
          remediation: `Add attestation conditions to statement '${sid}' of key "${keyId}", or add a Deny with a Null kms:RecipientAttestation condition so unattested calls fail closed`,
          evidence: { sid },
        };
      }
      return null;
    },
  },
  {
    // Attestation-bound statements should also bind a deployment context, not just an image identity.
    checkId: 'kms_key_enclave_attestation_no_deployment_binding',
    evaluate: ({ keyId, statements }) => {
      const attested = statements.filter(
        (statement) =>
          statement.Effect === 'Allow' &&
          statementTargetsSensitiveActions(statement) &&
          attestationConditionKeys(statement).length > 0
      );
      // No attestation-bound statements at all → covered by kms_key_enclave_attestation_not_enforced.
      if (attested.length === 0) return null;
      const missing = attested
        .filter((statement) => !statementBindsDeployment(statement))
        .map((statement) => String(statement.Sid ?? '<unnamed>'));
      if (missing.length === 0) return null;
      return {
        message: `KMS enclave key "${keyId}" enforces attestation but statement(s) ${missing.join(', ')} lack deployment-context binding (PCR3 role, PCR4 instance ID, PCR8 signing cert, or account-level condition)`,
        remediation: `Pair the image PCR bindings on "${keyId}" with PCR3 (parent IAM role), PCR4 (instance ID), PCR8 (signing certificate) or an account-level condition so attestation binds where the enclave runs`,
        evidence: { statementsWithoutBinding: missing },
      };
    },
  },
];

export class KMSScanner extends BaseScanner {
  constructor(client: AWSClient) {
    super(client, 'KMS');
  }

  async scan(_options?: ScannerOptions): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      logger.info('Starting KMS security scan...');

      const aliasesByKeyId = await this.listAliasesByKeyId();
      const keys = await this.listKeys();
      for (const keyId of keys) {
        logger.debug(`Scanning KMS key: ${keyId}`);

        const keyFindings = await this.validateKey(keyId, aliasesByKeyId.get(keyId) ?? []);
        findings.push(...keyFindings);
      }

      logger.info(`KMS scan complete. Found ${findings.length} findings.`);
    } catch (error) {
      logger.error('KMS scan failed', { error: (error as Error).message });
    }

    return findings;
  }

  private async listKeys(): Promise<string[]> {
    return retry(async () => {
      logger.debug('Fetching KMS keys...');
      const keys: string[] = [];
      let marker: string | undefined;

      do {
        const result = await this.client.kms.send(
          new ListKeysCommand({ Marker: marker, Limit: 1000 })
        );
        keys.push(...(result.Keys?.map(k => k.KeyId || '') || []));
        marker = result.NextMarker;
      } while (marker);

      return keys;
    });
  }

  private async validateKey(keyId: string, aliases: string[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];

    try {
      const details = await retry(async () => {
        const cmd = new DescribeKeyCommand({ KeyId: keyId });
        return await this.client.kms.send(cmd);
      });

      if (!details.KeyMetadata) return findings;

      const metadata = details.KeyMetadata;

      // Check if key is pending deletion
      if (metadata.KeyState === 'PendingDeletion') {
        findings.push(this.emit(
          'kms_cmk_not_deleted_unintentionally',
          { keyId, state: metadata.KeyState },
          {
            message: `KMS key ${keyId} is pending deletion`,
          }
        ));
      }

      // Check if key is disabled
      if (metadata.KeyState === 'Disabled') {
        findings.push(this.emit(
          'kms_cmk_are_used',
          { keyId, state: metadata.KeyState },
          {
            message: `KMS key ${keyId} is disabled`,
            remediation: `Enable KMS key ${keyId} if it's still needed`,
          }
        ));
      }

      // Check rotation for customer-managed keys
      if (metadata.KeyManager === 'CUSTOMER') {
        try {
          const rotationStatus = await repeat(async () => {
            const cmd = new GetKeyRotationStatusCommand({ KeyId: keyId });
            return await this.client.kms.send(cmd);
          });

          if (!rotationStatus.KeyRotationEnabled) {
            findings.push(this.emit(
              'kms_cmk_rotation_enabled',
              { keyId, rotationEnabled: rotationStatus.KeyRotationEnabled },
              {
                message: `Customer-managed KMS key ${keyId} does not have automatic rotation enabled`,
                remediation: `Enable automatic key rotation for customer-managed KMS key ${keyId}`,
              }
            ));
          }
        } catch (error) {
          logger.debug(`Failed to check rotation for key ${keyId}`, { error: (error as Error).message });
        }

        findings.push(...(await this.validateCustomerKeyPolicy(keyId, metadata, aliases)));
      }
    } catch (error) {
      logger.debug(`Failed to validate KMS key ${keyId}`, { error: (error as Error).message });
    }

    return findings;
  }

  /** Policy-driven checks for enabled customer-managed keys (multi-region, public access, enclave attestation family). */
  private async validateCustomerKeyPolicy(keyId: string, metadata: any, aliases: string[]): Promise<ScanningResult[]> {
    const findings: ScanningResult[] = [];
    if (metadata.KeyState !== 'Enabled') return findings;

    // kms_cmk_not_multi_region
    if (metadata.MultiRegion) {
      findings.push(this.emit(
        'kms_cmk_not_multi_region',
        { keyId, multiRegion: true },
        {
          message: `Customer-managed KMS key ${keyId} is a multi-region key`,
          remediation: `Migrate data protected by key ${keyId} to a single-region key unless cross-region key material replication is a documented requirement`,
        }
      ));
    }

    const policy = await this.getKeyPolicy(keyId);
    const tags = await this.listKeyTags(keyId);

    // kms_key_not_publicly_accessible
    if (policy && isPolicyPublic(policy)) {
      findings.push(this.emit(
        'kms_key_not_publicly_accessible',
        { keyId, publicPrincipal: true },
        {
          message: `KMS key ${keyId} may be publicly accessible: its key policy allows a wildcard principal without a restrictive condition`,
          remediation: `Replace the wildcard principal in the key policy of ${keyId} with specific account or role ARNs, or add a restrictive condition`,
        }
      ));
    }

    // Nitro Enclave attestation family (table-driven; requires the key policy)
    const description: string = metadata.Description ?? '';
    if (policy && isEnclaveKey({ description, tags, aliases, policy })) {
      const statements = toArray(policy.Statement).filter((s: any) => s && typeof s === 'object');
      for (const check of ENCLAVE_POLICY_CHECKS) {
        const failure = check.evaluate({ keyId, statements });
        if (failure) {
          findings.push(this.emit(
            check.checkId,
            { keyId, ...failure.evidence },
            { message: failure.message, remediation: failure.remediation }
          ));
        }
      }
    }

    return findings;
  }

  private async getKeyPolicy(keyId: string): Promise<any | null> {
    try {
      const result = await retry(async () => {
        return await this.client.kms.send(new GetKeyPolicyCommand({ KeyId: keyId, PolicyName: 'default' }));
      });
      return result.Policy ? JSON.parse(result.Policy) : null;
    } catch (error) {
      logger.debug(`Failed to fetch policy for KMS key ${keyId}`, { error: (error as Error).message });
      return null;
    }
  }

  private async listKeyTags(keyId: string): Promise<any[]> {
    try {
      const tags: any[] = [];
      let marker: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.client.kms.send(new ListResourceTagsCommand({ KeyId: keyId, Marker: marker }));
        });
        tags.push(...(result.Tags ?? []));
        marker = result.Truncated ? result.NextMarker : undefined;
      } while (marker);
      return tags;
    } catch (error) {
      logger.debug(`Failed to list tags for KMS key ${keyId}`, { error: (error as Error).message });
      return [];
    }
  }

  private async listAliasesByKeyId(): Promise<Map<string, string[]>> {
    const aliasesByKeyId = new Map<string, string[]>();
    try {
      let marker: string | undefined;
      do {
        const result = await retry(async () => {
          return await this.client.kms.send(new ListAliasesCommand({ Marker: marker, Limit: 100 }));
        });
        for (const alias of result.Aliases ?? []) {
          if (!alias.TargetKeyId || !alias.AliasName) continue;
          const list = aliasesByKeyId.get(alias.TargetKeyId) ?? [];
          list.push(alias.AliasName);
          aliasesByKeyId.set(alias.TargetKeyId, list);
        }
        marker = result.Truncated ? result.NextMarker : undefined;
      } while (marker);
    } catch (error) {
      logger.debug('Failed to list KMS aliases', { error: (error as Error).message });
    }
    return aliasesByKeyId;
  }
}

// Helper function
async function repeat<T>(fn: () => Promise<T>, maxRetries: number = 3, delayMs: number = 1000): Promise<T> {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, delayMs * Math.pow(2, i)));
    }
  }
  throw new Error('Retry failed');
}

export default KMSScanner;
