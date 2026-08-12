/**
 * Alert Service
 *
 * Sends notifications across four channels:
 *   SLACK       — Incoming Webhook (rich Block Kit message)
 *   EMAIL_SMTP  — Client's own mail server via nodemailer
 *   EMAIL_O365  — Microsoft Graph API (app-only, client credentials)
 *   EMAIL_GMAIL — Google Workspace Gmail API (service account delegation)
 *
 * All sensitive channel config is AES-encrypted at rest using the same
 * credentialService used for cloud credentials.
 */

import * as crypto   from 'crypto';
import * as https    from 'https';
import nodemailer    from 'nodemailer';
import { gmail as gmailApi } from '@googleapis/gmail';
import { JWT }       from 'google-auth-library';
import { prisma }    from '../config/database';
import { logger }    from '../config/logger';
import { env }       from '../config/env';
import type { ConfigChange, AlertConfig, AlertChannel } from '@prisma/client';

// ─── Encryption (reuse same key as credential service) ────────────────────────

const ALGO    = 'aes-256-gcm';
const ENC_KEY = Buffer.from(env.CREDENTIAL_ENCRYPTION_KEY, 'hex'); // 32-byte key

export function encryptAlertConfig(plain: Record<string, unknown>): string {
  const iv         = crypto.randomBytes(12);
  const cipher     = crypto.createCipheriv(ALGO, ENC_KEY, iv);
  const encrypted  = Buffer.concat([cipher.update(JSON.stringify(plain), 'utf8'), cipher.final()]);
  const tag        = cipher.getAuthTag();
  return [iv.toString('hex'), tag.toString('hex'), encrypted.toString('hex')].join(':');
}

export function decryptAlertConfig(enc: string): Record<string, unknown> {
  const [ivHex, tagHex, dataHex] = enc.split(':');
  const iv         = Buffer.from(ivHex,  'hex');
  const tag        = Buffer.from(tagHex, 'hex');
  const data       = Buffer.from(dataHex,'hex');
  const decipher   = crypto.createDecipheriv(ALGO, ENC_KEY, iv);
  decipher.setAuthTag(tag);
  const plain      = Buffer.concat([decipher.update(data), decipher.final()]);
  return JSON.parse(plain.toString('utf8')) as Record<string, unknown>;
}

// ─── HTML email template ───────────────────────────────────────────────────────

export function buildEmailHtml(change: ConfigChange, isFreeze: boolean): string {
  const sevColor: Record<string, string> = {
    CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#ca8a04', LOW: '#2563eb',
  };
  const color = sevColor[change.severity] ?? '#6b7280';
  const freezeBanner = isFreeze
    ? `<div style="background:#fee2e2;border-left:4px solid #dc2626;padding:12px 16px;margin-bottom:16px;border-radius:4px;">
         <strong style="color:#dc2626;">⚠ CHANGE FREEZE VIOLATION</strong>
         <p style="margin:4px 0 0;color:#7f1d1d;font-size:13px;">This change occurred during an active change freeze window.</p>
       </div>`
    : '';

  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f9fafb;margin:0;padding:24px;">
  <div style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:8px;border:1px solid #e5e7eb;overflow:hidden;">

    <!-- Header -->
    <div style="background:#1e293b;padding:20px 24px;display:flex;align-items:center;gap:12px;">
      <span style="font-size:20px;">🛡️</span>
      <div>
        <p style="margin:0;color:#f8fafc;font-size:16px;font-weight:600;">Cloud Config Change Alert</p>
        <p style="margin:2px 0 0;color:#94a3b8;font-size:12px;">${change.provider} · ${new Date(change.eventTime).toUTCString()}</p>
      </div>
    </div>

    <div style="padding:24px;">
      ${freezeBanner}

      <!-- Severity badge + risk score -->
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
        <span style="background:${color};color:#fff;padding:4px 12px;border-radius:9999px;font-size:12px;font-weight:700;letter-spacing:.5px;">
          ${change.severity}
        </span>
        <span style="font-size:13px;color:#6b7280;">Risk Score: <strong style="color:${color};">${change.riskScore}</strong></span>
        <span style="font-size:13px;color:#6b7280;">Category: <strong>${change.category}</strong></span>
      </div>

      <!-- Event -->
      <table style="width:100%;border-collapse:collapse;font-size:13px;">
        <tr style="border-bottom:1px solid #f3f4f6;">
          <td style="padding:8px 0;color:#9ca3af;width:130px;vertical-align:top;">Event</td>
          <td style="padding:8px 0;font-weight:600;color:#111827;">${change.eventName}</td>
        </tr>
        <tr style="border-bottom:1px solid #f3f4f6;">
          <td style="padding:8px 0;color:#9ca3af;vertical-align:top;">Summary</td>
          <td style="padding:8px 0;color:#374151;">${change.summary}</td>
        </tr>
        ${change.actor ? `<tr style="border-bottom:1px solid #f3f4f6;">
          <td style="padding:8px 0;color:#9ca3af;">Actor</td>
          <td style="padding:8px 0;color:#374151;">${change.actor} ${change.actorType ? `<span style="color:#9ca3af;">(${change.actorType})</span>` : ''}</td>
        </tr>` : ''}
        ${change.sourceIp ? `<tr style="border-bottom:1px solid #f3f4f6;">
          <td style="padding:8px 0;color:#9ca3af;">Source IP</td>
          <td style="padding:8px 0;font-family:monospace;color:#374151;">${change.sourceIp}</td>
        </tr>` : ''}
        ${change.resourceType ? `<tr style="border-bottom:1px solid #f3f4f6;">
          <td style="padding:8px 0;color:#9ca3af;">Resource Type</td>
          <td style="padding:8px 0;color:#374151;">${change.resourceType}</td>
        </tr>` : ''}
        ${change.resourceName || change.resourceId ? `<tr style="border-bottom:1px solid #f3f4f6;">
          <td style="padding:8px 0;color:#9ca3af;">Resource</td>
          <td style="padding:8px 0;font-family:monospace;color:#374151;">${change.resourceName ?? change.resourceId}</td>
        </tr>` : ''}
        ${change.region ? `<tr>
          <td style="padding:8px 0;color:#9ca3af;">Region</td>
          <td style="padding:8px 0;color:#374151;">${change.region}</td>
        </tr>` : ''}
      </table>

      <!-- CTA -->
      <div style="margin-top:24px;text-align:center;">
        <a href="${env.CORS_ORIGIN}/config-changes"
           style="display:inline-block;background:#2563eb;color:#fff;padding:10px 24px;border-radius:6px;font-size:14px;font-weight:600;text-decoration:none;">
          View in Dashboard →
        </a>
      </div>
    </div>

    <div style="background:#f8fafc;padding:12px 24px;text-align:center;font-size:11px;color:#9ca3af;border-top:1px solid #e5e7eb;">
      Cloud Security Scanner · Alert generated at ${new Date().toUTCString()}
    </div>
  </div>
</body>
</html>`;
}

// ─── Slack Block Kit message ──────────────────────────────────────────────────

export function buildSlackPayload(change: ConfigChange, isFreeze: boolean): Record<string, unknown> {
  const sevEmoji: Record<string, string> = {
    CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵',
  };
  const emoji = sevEmoji[change.severity] ?? '⚪';

  const blocks: unknown[] = [
    {
      type: 'header',
      text: { type: 'plain_text', text: `${emoji} ${isFreeze ? '🚨 FREEZE VIOLATION — ' : ''}Config Change Alert`, emoji: true },
    },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*Severity*\n${change.severity}` },
        { type: 'mrkdwn', text: `*Risk Score*\n${change.riskScore}` },
        { type: 'mrkdwn', text: `*Category*\n${change.category}` },
        { type: 'mrkdwn', text: `*Provider*\n${change.provider}` },
      ],
    },
    {
      type: 'section',
      text: { type: 'mrkdwn', text: `*Event:* \`${change.eventName}\`\n*Summary:* ${change.summary}` },
    },
  ];

  if (change.actor || change.sourceIp || change.region) {
    blocks.push({
      type: 'section',
      fields: [
        change.actor   ? { type: 'mrkdwn', text: `*Actor*\n${change.actor}` }    : null,
        change.sourceIp ? { type: 'mrkdwn', text: `*Source IP*\n\`${change.sourceIp}\`` } : null,
        change.region  ? { type: 'mrkdwn', text: `*Region*\n${change.region}` } : null,
        change.resourceName ? { type: 'mrkdwn', text: `*Resource*\n\`${change.resourceName}\`` } : null,
      ].filter(Boolean),
    });
  }

  if (isFreeze) {
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: ':warning: *This change occurred during an active change freeze window.*' },
    });
  }

  blocks.push({
    type: 'actions',
    elements: [{
      type: 'button',
      text: { type: 'plain_text', text: 'View in Dashboard' },
      url:  `${env.CORS_ORIGIN}/config-changes`,
      style: 'primary',
    }],
  });

  blocks.push({ type: 'divider' });

  return {
    text: `${emoji} Config Change: ${change.eventName} (${change.severity})`,
    blocks,
  };
}

// ─── Channel senders ──────────────────────────────────────────────────────────

export async function sendSlack(cfg: Record<string, unknown>, payload: Record<string, unknown>): Promise<void> {
  const webhookUrl = cfg.webhookUrl as string;
  if (!webhookUrl) throw new Error('Slack webhookUrl missing');

  const body = JSON.stringify(payload);
  await new Promise<void>((resolve, reject) => {
    const url  = new URL(webhookUrl);
    const req  = https.request({
      hostname: url.hostname,
      path:     url.pathname + url.search,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      res.resume();
      res.statusCode === 200 ? resolve() : reject(new Error(`Slack returned HTTP ${res.statusCode}`));
    });
    req.on('error', reject);
    req.setTimeout(10_000, () => { req.destroy(); reject(new Error('Slack request timed out')); });
    req.write(body);
    req.end();
  });
}

export async function sendSmtp(cfg: Record<string, unknown>, subject: string, html: string): Promise<void> {
  const transport = nodemailer.createTransport({
    host:   cfg.host   as string,
    port:   (cfg.port  as number) ?? 587,
    secure: (cfg.secure as boolean) ?? false,
    auth: {
      user: cfg.user     as string,
      pass: cfg.password as string,
    },
    tls: { rejectUnauthorized: false },
  });

  await transport.sendMail({
    from:    cfg.from as string,
    to:      (cfg.to  as string[]).join(', '),
    subject,
    html,
  });
  transport.close();
}

export async function sendO365(cfg: Record<string, unknown>, subject: string, html: string): Promise<void> {
  // Step 1: acquire token via client credentials (app-only)
  const tenantId     = cfg.tenantId     as string;
  const clientId     = cfg.clientId     as string;
  const clientSecret = cfg.clientSecret as string;
  const fromEmail    = cfg.fromEmail    as string;
  const toEmails     = cfg.toEmails     as string[];

  const tokenBody = new URLSearchParams({
    grant_type:    'client_credentials',
    client_id:     clientId,
    client_secret: clientSecret,
    scope:         'https://graph.microsoft.com/.default',
  }).toString();

  const tokenData = await new Promise<Record<string, unknown>>((resolve, reject) => {
    const req = https.request({
      hostname: 'login.microsoftonline.com',
      path:     `/${tenantId}/oauth2/v2.0/token`,
      method:   'POST',
      headers:  { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(tokenBody) },
    }, (res) => {
      let data = '';
      res.on('data', (c: Buffer) => { data += c; });
      res.on('end', () => {
        try { resolve(JSON.parse(data) as Record<string, unknown>); }
        catch { reject(new Error('Invalid token response')); }
      });
    });
    req.on('error', reject);
    req.write(tokenBody);
    req.end();
  });

  if (!tokenData.access_token) {
    throw new Error(`O365 token error: ${String(tokenData.error_description ?? tokenData.error ?? 'unknown')}`);
  }

  // Step 2: send via Graph API
  const mailPayload = JSON.stringify({
    message: {
      subject,
      body:         { contentType: 'HTML', content: html },
      toRecipients: toEmails.map((email) => ({ emailAddress: { address: email } })),
    },
    saveToSentItems: false,
  });

  await new Promise<void>((resolve, reject) => {
    const req = https.request({
      hostname: 'graph.microsoft.com',
      path:     `/v1.0/users/${fromEmail}/sendMail`,
      method:   'POST',
      headers:  {
        'Authorization':  `Bearer ${tokenData.access_token as string}`,
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(mailPayload),
      },
    }, (res) => {
      res.resume();
      res.statusCode && res.statusCode < 300 ? resolve() : reject(new Error(`Graph API returned HTTP ${res.statusCode}`));
    });
    req.on('error', reject);
    req.write(mailPayload);
    req.end();
  });
}

export async function sendGmail(cfg: Record<string, unknown>, subject: string, html: string): Promise<void> {
  const fromEmail = cfg.fromEmail as string;
  const toEmails  = cfg.toEmails  as string[];
  const keyJson   = cfg.serviceAccountKey as string;

  const serviceAccountKey = JSON.parse(keyJson) as Record<string, unknown>;

  // Service account with domain-wide delegation
  const auth = new JWT({
    email:      serviceAccountKey.client_email as string,
    key:        serviceAccountKey.private_key  as string,
    scopes:     ['https://www.googleapis.com/auth/gmail.send'],
    subject:    fromEmail,  // impersonate this Workspace user
  });

  const gmail = gmailApi({ version: 'v1', auth });

  // Build RFC 2822 raw message
  const boundary = `boundary_${Date.now()}`;
  const raw = [
    `From: ${fromEmail}`,
    `To: ${toEmails.join(', ')}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/html; charset=UTF-8',
    '',
    html,
    `--${boundary}--`,
  ].join('\r\n');

  const encoded = Buffer.from(raw).toString('base64url');
  await gmail.users.messages.send({ userId: 'me', requestBody: { raw: encoded } });
}

// ─── Subject builder ──────────────────────────────────────────────────────────

function buildSubject(change: ConfigChange, isFreeze: boolean): string {
  const prefix = isFreeze ? '[FREEZE VIOLATION] ' : `[${change.severity}] `;
  return `${prefix}${change.provider} Config Change: ${change.eventName}`;
}

// ─── Public: dispatch a change to all matching alert configs ──────────────────

export async function dispatchAlerts(change: ConfigChange): Promise<void> {
  const isFreeze = change.freezeViolation;

  // Load active configs
  const configs = await prisma.alertConfig.findMany({ where: { isActive: true } });

  for (const config of configs) {
    // Filter: onFreezeOnly configs skip non-freeze changes
    if (config.onFreezeOnly && !isFreeze) continue;

    // Filter: severity threshold
    const sevOrder = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    if (sevOrder.indexOf(change.severity) < sevOrder.indexOf(config.minSeverity)) continue;

    // Filter: category
    if (config.categories.length > 0 && !config.categories.includes(change.category)) continue;

    // Filter: provider
    if (config.providers.length > 0 && !config.providers.includes(change.provider)) continue;

    // Filter: targetId
    const targetId = change.awsAccountId ?? change.azureSubId ?? change.gcpProjectId ?? '';
    if (config.targetIds.length > 0 && !config.targetIds.includes(targetId)) continue;

    // Send
    let status       = 'SENT';
    let errorMessage: string | undefined;

    try {
      const cfg     = decryptAlertConfig(config.encryptedConfig);
      const subject = buildSubject(change, isFreeze);
      const html    = buildEmailHtml(change, isFreeze);
      const slack   = buildSlackPayload(change, isFreeze);

      switch (config.channel as AlertChannel) {
        case 'SLACK':       await sendSlack(cfg, slack); break;
        case 'EMAIL_SMTP':  await sendSmtp(cfg, subject, html); break;
        case 'EMAIL_O365':  await sendO365(cfg, subject, html); break;
        case 'EMAIL_GMAIL': await sendGmail(cfg, subject, html); break;
      }

      logger.info(`[alert] Sent via ${config.channel} for change ${change.id} (config: ${config.name})`);
    } catch (err) {
      status       = 'FAILED';
      errorMessage = (err as Error).message;
      logger.warn(`[alert] Failed ${config.channel} (${config.name}): ${errorMessage}`);
    }

    await prisma.alertLog.create({
      data: {
        configId:     config.id,
        changeId:     change.id,
        subject:      buildSubject(change, isFreeze),
        status,
        errorMessage: errorMessage ?? null,
      },
    });
  }
}
