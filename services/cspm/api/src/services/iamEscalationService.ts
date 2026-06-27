/**
 * IAM Privilege Escalation Detection Service
 *
 * Analyses every new ConfigChange for patterns that indicate privilege escalation:
 *   - Policy attachment (managed / inline) to users, roles, groups
 *   - Root account activity
 *   - Console credential creation / access key creation
 *   - Trust policy modification
 *   - Permission boundary deletion
 *   - Adding users to admin-equivalent groups
 *   - Azure: privileged role assignments
 *   - GCP: SetIamPolicy on high-value resources
 *
 * Called fire-and-forget from inventoryPipeline after each new change is stored.
 */

import { prisma } from '../config/database';
import { logger }  from '../config/logger';
import type { ConfigChange } from '@prisma/client';

// ─── Escalation pattern definitions ──────────────────────────────────────────

interface EscalationPattern {
  type:     string;
  severity: string;
  match:    (eventName: string, change: ConfigChange) => boolean;
  summary:  (change: ConfigChange) => string;
}

// AWS event name prefix helper
const awsIam = (name: string) => name.toLowerCase().includes(name.toLowerCase());

const AWS_PATTERNS: EscalationPattern[] = [
  {
    type: 'POLICY_ATTACH',
    severity: 'CRITICAL',
    match: (e) => /^iam:(Attach(User|Role|Group)Policy)$/i.test(e),
    summary: (c) => `Managed policy attached to ${c.resourceType ?? 'IAM principal'} "${c.resourceName ?? c.resourceId ?? 'unknown'}" by ${c.actor ?? 'unknown actor'}`,
  },
  {
    type: 'INLINE_POLICY',
    severity: 'CRITICAL',
    match: (e) => /^iam:Put(User|Role|Group)Policy$/i.test(e),
    summary: (c) => `Inline policy written to ${c.resourceType ?? 'IAM principal'} "${c.resourceName ?? c.resourceId ?? 'unknown'}" by ${c.actor ?? 'unknown actor'}`,
  },
  {
    type: 'TRUST_POLICY',
    severity: 'HIGH',
    match: (e) => /^iam:UpdateAssumeRolePolicy$/i.test(e),
    summary: (c) => `Trust policy (AssumeRolePolicy) updated on role "${c.resourceName ?? c.resourceId ?? 'unknown'}" by ${c.actor ?? 'unknown actor'}`,
  },
  {
    type: 'PERMISSION_BOUNDARY_DELETE',
    severity: 'HIGH',
    match: (e) => /^iam:Delete(User|Role)PermissionsBoundary$/i.test(e),
    summary: (c) => `Permissions boundary removed from ${c.resourceType ?? 'IAM principal'} "${c.resourceName ?? c.resourceId ?? 'unknown'}" by ${c.actor ?? 'unknown actor'}`,
  },
  {
    type: 'CREDENTIAL_CREATION',
    severity: 'HIGH',
    match: (e) => /^iam:(CreateLoginProfile|UpdateLoginProfile)$/i.test(e),
    summary: (c) => `Console login credentials created/updated for "${c.resourceName ?? c.resourceId ?? 'unknown'}" by ${c.actor ?? 'unknown actor'}`,
  },
  {
    type: 'ACCESS_KEY_CREATION',
    severity: 'HIGH',
    match: (e) => /^iam:CreateAccessKey$/i.test(e),
    summary: (c) => `Access key created for user "${c.resourceName ?? c.resourceId ?? 'unknown'}" by ${c.actor ?? 'unknown actor'}`,
  },
  {
    type: 'ADMIN_GROUP',
    severity: 'CRITICAL',
    match: (e, c) =>
      /^iam:AddUserToGroup$/i.test(e) &&
      /admin|root|superuser|full.?access/i.test(c.resourceName ?? c.resourceId ?? ''),
    summary: (c) => `User added to privileged group "${c.resourceName ?? c.resourceId ?? 'unknown'}" by ${c.actor ?? 'unknown actor'}`,
  },
  {
    type: 'ROLE_CREATION',
    severity: 'MEDIUM',
    match: (e) => /^iam:CreateRole$/i.test(e),
    summary: (c) => `New IAM role "${c.resourceName ?? c.resourceId ?? 'unknown'}" created by ${c.actor ?? 'unknown actor'}`,
  },
  {
    type: 'ROOT_ACTIVITY',
    severity: 'CRITICAL',
    match: (_e, c) => /^root$/i.test(c.actorType ?? '') || /root/i.test(c.actor ?? ''),
    summary: (c) => `Root account activity detected: ${c.eventName} on ${c.resourceType ?? 'resource'} "${c.resourceName ?? c.resourceId ?? 'unknown'}"`,
  },
  {
    type: 'STS_ASSUME_ROLE',
    severity: 'MEDIUM',
    match: (e) => /^sts:AssumeRole$/i.test(e),
    summary: (c) => `Role assumption via STS by "${c.actor ?? 'unknown'}" — role: "${c.resourceName ?? c.resourceId ?? 'unknown'}"`,
  },
  {
    type: 'POLICY_CREATION',
    severity: 'MEDIUM',
    match: (e) => /^iam:CreatePolicy$/i.test(e),
    summary: (c) => `New IAM policy "${c.resourceName ?? c.resourceId ?? 'unknown'}" created by ${c.actor ?? 'unknown actor'}`,
  },
];

const AZURE_PATTERNS: EscalationPattern[] = [
  {
    type: 'POLICY_ATTACH',
    severity: 'CRITICAL',
    match: (e) => /roleAssignments\/write/i.test(e),
    summary: (c) => `Azure role assignment created on "${c.resourceName ?? c.resourceId ?? 'unknown'}" by ${c.actor ?? 'unknown actor'}`,
  },
  {
    type: 'ROLE_CREATION',
    severity: 'HIGH',
    match: (e) => /roleDefinitions\/write/i.test(e),
    summary: (c) => `Custom Azure role definition created/updated by ${c.actor ?? 'unknown actor'}`,
  },
  {
    type: 'ADMIN_GROUP',
    severity: 'CRITICAL',
    match: (e) => /groups.*members\/\$ref|addMember/i.test(e),
    summary: (c) => `Member added to Azure AD group "${c.resourceName ?? 'unknown'}" by ${c.actor ?? 'unknown actor'}`,
  },
  {
    type: 'CREDENTIAL_CREATION',
    severity: 'HIGH',
    match: (e) => /applications.*addPassword|servicePrincipals.*addPassword/i.test(e),
    summary: (c) => `Credential (secret/certificate) added to application/service principal by ${c.actor ?? 'unknown actor'}`,
  },
];

const GCP_PATTERNS: EscalationPattern[] = [
  {
    type: 'POLICY_ATTACH',
    severity: 'CRITICAL',
    match: (e) => /setIamPolicy/i.test(e),
    summary: (c) => `IAM policy updated on GCP resource "${c.resourceName ?? c.resourceId ?? 'unknown'}" by ${c.actor ?? 'unknown actor'}`,
  },
  {
    type: 'ROLE_CREATION',
    severity: 'HIGH',
    match: (e) => /roles\.create|roles\.update/i.test(e),
    summary: (c) => `Custom GCP role created/updated by ${c.actor ?? 'unknown actor'}`,
  },
  {
    type: 'ACCESS_KEY_CREATION',
    severity: 'HIGH',
    match: (e) => /serviceAccounts\.keys\.create/i.test(e),
    summary: (c) => `Service account key created for "${c.resourceName ?? 'unknown'}" by ${c.actor ?? 'unknown actor'}`,
  },
  {
    type: 'TRUST_POLICY',
    severity: 'HIGH',
    match: (e) => /serviceAccounts\.update|iam\.serviceAccounts\.actAs/i.test(e),
    summary: (c) => `Service account trust / actAs permission modified by ${c.actor ?? 'unknown actor'}`,
  },
];

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Analyses a new ConfigChange for IAM privilege escalation indicators.
 * Creates an IamEscalationEvent record if a pattern matches.
 * Safe to call fire-and-forget.
 */
export async function analyzeForEscalation(change: ConfigChange): Promise<void> {
  try {
    const patterns =
      change.provider === 'AWS'   ? AWS_PATTERNS   :
      change.provider === 'AZURE' ? AZURE_PATTERNS :
      GCP_PATTERNS;

    for (const pattern of patterns) {
      if (!pattern.match(change.eventName, change)) continue;

      await prisma.iamEscalationEvent.create({
        data: {
          provider:       change.provider,
          targetId:       change.awsAccountId ?? change.azureSubId ?? change.gcpProjectId ?? change.provider,
          changeId:       change.id,
          escalationType: pattern.type,
          severity:       pattern.severity,
          actor:          change.actor,
          actorType:      change.actorType,
          targetPrincipal: change.resourceId,
          resourceId:     change.resourceId,
          resourceType:   change.resourceType,
          eventName:      change.eventName,
          eventTime:      change.eventTime,
          summary:        pattern.summary(change),
          details:        {
            sourceIp:  change.sourceIp,
            changeId:  change.id,
            category:  change.category,
            newValue:  change.newValue,
          } as object,
        },
      });

      logger.warn(
        `[iam-escalation] ${pattern.type} detected — ${change.provider}:${change.eventName} by ${change.actor ?? 'unknown'}`
      );
      // A single event can match at most one pattern (first wins)
      break;
    }
  } catch (err) {
    logger.error('[iam-escalation] Analysis failed', err);
  }
}

/**
 * Retroactively scan existing ConfigChanges for a given provider+targetId.
 * Useful for initial analysis after feature rollout.
 */
export async function backfillEscalationScan(provider: string, targetId: string): Promise<number> {
  const where =
    provider === 'AWS'   ? { awsAccountId: targetId } :
    provider === 'AZURE' ? { azureSubId:   targetId } :
    { gcpProjectId: targetId };

  const changes = await prisma.configChange.findMany({
    where: { ...where, iamEscalations: { none: {} } }, // skip already-analyzed
    orderBy: { eventTime: 'desc' },
    take: 2000,
  });

  let found = 0;
  for (const change of changes) {
    const before = found;
    await analyzeForEscalation(change);
    // We can't easily know if a new record was created without another query, so approximate
    found = before; // just count batches processed
  }

  return changes.length;
}
