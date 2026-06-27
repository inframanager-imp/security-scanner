/**
 * External Integration Service
 *
 * Dispatches ConfigChange notifications to:
 *   WEBHOOK    — HTTP POST with HMAC-SHA256 signature header
 *   SERVICENOW — Creates incident via Table API
 *   JIRA       — Creates issue via REST API v3
 *
 * Config is encrypted at rest (AES-256-GCM, same key as alertService).
 * Called fire-and-forget from inventoryPipeline alongside dispatchAlerts.
 */

import * as https  from 'https';
import * as http   from 'http';
import * as crypto from 'crypto';
import { prisma }  from '../config/database';
import { logger }  from '../config/logger';
import { env }     from '../config/env';
import type { ConfigChange } from '@prisma/client';

// ─── Encryption (re-uses same key as credentialService) ──────────────────────

const KEY = Buffer.from(env.CREDENTIAL_ENCRYPTION_KEY, 'hex');

export function encryptIntegrationConfig(cfg: Record<string, string>): string {
  const iv         = crypto.randomBytes(12);
  const cipher     = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const encrypted  = Buffer.concat([cipher.update(JSON.stringify(cfg), 'utf8'), cipher.final()]);
  const tag        = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

export function decryptIntegrationConfig(enc: string): Record<string, string> {
  const buf       = Buffer.from(enc, 'base64');
  const iv        = buf.subarray(0, 12);
  const tag       = buf.subarray(12, 28);
  const encrypted = buf.subarray(28);
  const decipher  = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  return JSON.parse(decipher.update(encrypted).toString('utf8') + decipher.final('utf8')) as Record<string, string>;
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

function httpPost(
  url: string,
  body: string,
  headers: Record<string, string>,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const parsed  = new URL(url);
    const lib     = parsed.protocol === 'https:' ? https : http;
    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), ...headers },
    };
    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', (chunk: Buffer) => { data += chunk.toString(); });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Severity / priority maps ─────────────────────────────────────────────────

const SEV_TO_SN_URGENCY: Record<string, string> = {
  CRITICAL: '1', HIGH: '2', MEDIUM: '3', LOW: '4',
};
const SEV_TO_JIRA_PRIORITY: Record<string, string> = {
  CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low',
};

// ─── Channel implementations ──────────────────────────────────────────────────

async function sendWebhook(cfg: Record<string, string>, change: ConfigChange): Promise<string> {
  const payload = JSON.stringify({
    event:        'config_change',
    id:           change.id,
    provider:     change.provider,
    severity:     change.severity,
    category:     change.category,
    eventName:    change.eventName,
    eventTime:    change.eventTime.toISOString(),
    resourceType: change.resourceType,
    resourceName: change.resourceName,
    resourceId:   change.resourceId,
    actor:        change.actor,
    summary:      change.summary,
    freezeViolation: change.freezeViolation,
  });

  const headers: Record<string, string> = {};
  if (cfg.secret) {
    const sig = crypto.createHmac('sha256', cfg.secret).update(payload).digest('hex');
    headers['X-Scanner-Signature'] = `sha256=${sig}`;
  }
  if (cfg.authHeader) headers['Authorization'] = cfg.authHeader;

  const res = await httpPost(cfg.url, payload, headers);
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`Webhook returned HTTP ${res.status}: ${res.body.slice(0, 200)}`);
  }
  return `HTTP ${res.status}`;
}

async function sendServiceNow(cfg: Record<string, string>, change: ConfigChange): Promise<string> {
  const url   = `${cfg.instanceUrl}/api/now/table/incident`;
  const creds = Buffer.from(`${cfg.username}:${cfg.password}`).toString('base64');
  const body  = JSON.stringify({
    short_description:  `[${change.provider}] ${change.severity} — ${change.eventName}`,
    description:        [
      `Provider:      ${change.provider}`,
      `Severity:      ${change.severity}`,
      `Category:      ${change.category}`,
      `Event:         ${change.eventName}`,
      `Time:          ${change.eventTime.toISOString()}`,
      `Resource:      ${change.resourceType ?? ''} / ${change.resourceName ?? change.resourceId ?? ''}`,
      `Actor:         ${change.actor ?? 'unknown'}`,
      `Summary:       ${change.summary}`,
      `Freeze:        ${change.freezeViolation ? 'YES — freeze window violation' : 'No'}`,
    ].join('\n'),
    urgency:            SEV_TO_SN_URGENCY[change.severity] ?? '3',
    impact:             SEV_TO_SN_URGENCY[change.severity] ?? '3',
    category:           'Security',
    subcategory:        'Cloud Configuration Change',
    caller_id:          cfg.callerId ?? 'aws-scanner',
  });

  const res = await httpPost(url, body, { Authorization: `Basic ${creds}` });
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`ServiceNow returned HTTP ${res.status}: ${res.body.slice(0, 200)}`);
  }
  const parsed = JSON.parse(res.body) as { result?: { sys_id?: string; number?: string } };
  return parsed.result?.number ?? parsed.result?.sys_id ?? 'created';
}

async function sendJira(cfg: Record<string, string>, change: ConfigChange): Promise<string> {
  const url   = `${cfg.baseUrl}/rest/api/3/issue`;
  const creds = Buffer.from(`${cfg.email}:${cfg.apiToken}`).toString('base64');

  const body = JSON.stringify({
    fields: {
      project:     { key: cfg.projectKey },
      summary:     `[${change.provider}] ${change.severity} — ${change.eventName} on ${change.resourceName ?? change.resourceId ?? 'unknown'}`,
      description: {
        type:    'doc',
        version: 1,
        content: [{
          type:    'paragraph',
          content: [{
            type: 'text',
            text: [
              `Provider: ${change.provider}`,
              `Severity: ${change.severity}`,
              `Category: ${change.category}`,
              `Event: ${change.eventName}`,
              `Time: ${change.eventTime.toISOString()}`,
              `Resource: ${change.resourceType ?? ''} / ${change.resourceName ?? change.resourceId ?? ''}`,
              `Actor: ${change.actor ?? 'unknown'}`,
              `Summary: ${change.summary}`,
              `Freeze violation: ${change.freezeViolation ? 'YES' : 'No'}`,
            ].join('\n'),
          }],
        }],
      },
      issuetype:   { name: cfg.issueType ?? 'Bug' },
      priority:    { name: SEV_TO_JIRA_PRIORITY[change.severity] ?? 'Medium' },
      labels:      ['cloud-scanner', `severity-${change.severity.toLowerCase()}`, change.provider.toLowerCase()],
    },
  });

  const res = await httpPost(url, body, { Authorization: `Basic ${creds}` });
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`Jira returned HTTP ${res.status}: ${res.body.slice(0, 200)}`);
  }
  const parsed = JSON.parse(res.body) as { key?: string; id?: string };
  return parsed.key ?? parsed.id ?? 'created';
}

// ─── Severity filter helper ───────────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
function meetsMinSeverity(changeSev: string, minSev: string): boolean {
  return (SEV_ORDER[changeSev] ?? 0) >= (SEV_ORDER[minSev] ?? 0);
}

// ─── Public dispatcher ────────────────────────────────────────────────────────

export async function dispatchIntegrations(change: ConfigChange): Promise<void> {
  let configs;
  try {
    configs = await prisma.integrationConfig.findMany({
      where: { isActive: true },
    });
  } catch (err) {
    logger.error('[integrations] Failed to load configs', err);
    return;
  }

  await Promise.allSettled(
    configs.map(async (cfg) => {
      try {
        // Severity filter
        if (!meetsMinSeverity(change.severity, cfg.minSeverity)) return;

        // Provider scope
        if (cfg.providers.length > 0 && !cfg.providers.includes(change.provider)) return;

        // Target scope
        const changeTargetId = change.awsAccountId ?? change.azureSubId ?? change.gcpProjectId;
        if (cfg.targetIds.length > 0 && !cfg.targetIds.includes(changeTargetId ?? '')) return;

        // Freeze-only filter
        if (cfg.onFreezeOnly && !change.freezeViolation) return;

        const secret = decryptIntegrationConfig(cfg.encryptedConfig);
        let externalId: string;

        if (cfg.integrationType === 'WEBHOOK') {
          externalId = await sendWebhook(secret, change);
        } else if (cfg.integrationType === 'SERVICENOW') {
          externalId = await sendServiceNow(secret, change);
        } else {
          externalId = await sendJira(secret, change);
        }

        await prisma.integrationLog.create({
          data: { configId: cfg.id, changeId: change.id, status: 'SENT', externalId },
        });
        logger.debug(`[integrations] ${cfg.integrationType} "${cfg.name}" → ${externalId}`);
      } catch (err) {
        await prisma.integrationLog.create({
          data: {
            configId:     cfg.id,
            changeId:     change.id,
            status:       'FAILED',
            errorMessage: (err as Error).message.slice(0, 500),
          },
        }).catch(() => undefined);
        logger.warn(`[integrations] "${cfg.name}" failed: ${(err as Error).message}`);
      }
    }),
  );
}
