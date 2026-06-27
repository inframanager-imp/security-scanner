/**
 * Scheduled Report Service
 *
 * Generates rich HTML security reports and delivers them via email (nodemailer).
 * Reports open in-browser as print-ready HTML — user can File → Print → Save as PDF.
 * Scheduled delivery uses existing SMTP config via environment variables.
 *
 * Sections available:
 *   SUMMARY         — Open changes counts, posture score overview
 *   CONFIG_CHANGES  — Top recent changes by severity
 *   DRIFT           — Drift detection results per baseline
 *   IAM_ESCALATION  — Recent privilege escalation events
 *   POSTURE         — Current posture scores with grade breakdown
 */

import * as nodemailer from 'nodemailer';
import { prisma }       from '../config/database';
import { logger }       from '../config/logger';

// ─── Email transport ──────────────────────────────────────────────────────────

function getTransport() {
  return nodemailer.createTransport({
    host:   process.env.REPORT_SMTP_HOST   ?? 'localhost',
    port:   parseInt(process.env.REPORT_SMTP_PORT ?? '587'),
    secure: process.env.REPORT_SMTP_SECURE === 'true',
    auth: process.env.REPORT_SMTP_USER ? {
      user: process.env.REPORT_SMTP_USER,
      pass: process.env.REPORT_SMTP_PASS ?? '',
    } : undefined,
  });
}

// ─── Next-run calculator ──────────────────────────────────────────────────────

export function computeNextRun(
  frequency: string,
  hour: number,
  dayOfWeek?: number | null,
  dayOfMonth?: number | null,
): Date {
  const now  = new Date();
  const next = new Date();
  next.setMinutes(0, 0, 0);
  next.setHours(hour);

  if (frequency === 'DAILY') {
    if (next <= now) next.setDate(next.getDate() + 1);
  } else if (frequency === 'WEEKLY') {
    const target = dayOfWeek ?? 1; // Monday default
    const diff   = (target - now.getDay() + 7) % 7 || 7;
    next.setDate(now.getDate() + diff);
    if (diff === 0 && next <= now) next.setDate(next.getDate() + 7);
  } else if (frequency === 'MONTHLY') {
    const target = dayOfMonth ?? 1;
    next.setDate(target);
    if (next <= now) {
      next.setMonth(next.getMonth() + 1);
      next.setDate(target);
    }
  }
  return next;
}

// ─── Report data gatherer ─────────────────────────────────────────────────────

interface ReportData {
  title:        string;
  generatedAt:  string;
  provider?:    string;
  targetId?:    string;
  sections:     string[];
  summary?:     { critical: number; high: number; medium: number; low: number; total: number };
  configChanges?: Array<{ severity: string; category: string; eventName: string; resourceName: string | null; actor: string | null; eventTime: Date; summary: string; freezeViolation: boolean }>;
  driftResults?: Array<{ baselineName: string; driftType: string; resourceType: string; resourceName: string | null; severity: string; driftedFields: string[] }>;
  iamEscalations?: Array<{ escalationType: string; severity: string; actor: string | null; eventName: string; summary: string; eventTime: Date; status: string }>;
  postureScores?: Array<{ provider: string; targetId: string; score: number; grade: string; calculatedAt: Date }>;
}

async function gatherReportData(schedule: {
  provider: string | null;
  targetId: string | null;
  sections: string[];
  name: string;
}): Promise<ReportData> {
  const since30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const data: ReportData = {
    title:       schedule.name,
    generatedAt: new Date().toISOString(),
    provider:    schedule.provider ?? undefined,
    targetId:    schedule.targetId ?? undefined,
    sections:    schedule.sections,
  };

  const changeWhere = schedule.provider && schedule.targetId
    ? {
        provider: schedule.provider,
        ...(schedule.provider === 'AWS'   ? { awsAccountId: schedule.targetId } :
            schedule.provider === 'AZURE' ? { azureSubId:   schedule.targetId } :
            { gcpProjectId: schedule.targetId }),
        eventTime: { gte: since30d },
      }
    : { eventTime: { gte: since30d } };

  if (schedule.sections.includes('SUMMARY') || schedule.sections.includes('CONFIG_CHANGES')) {
    const bySev = await prisma.configChange.groupBy({
      by: ['severity'],
      where: { ...changeWhere, changeStatus: 'OPEN' },
      _count: { id: true },
    });
    const m = Object.fromEntries(bySev.map((r) => [r.severity, r._count.id]));
    data.summary = {
      critical: m['CRITICAL'] ?? 0,
      high:     m['HIGH']     ?? 0,
      medium:   m['MEDIUM']   ?? 0,
      low:      m['LOW']      ?? 0,
      total:    Object.values(m).reduce((s, n) => s + n, 0),
    };
  }

  if (schedule.sections.includes('CONFIG_CHANGES')) {
    data.configChanges = await prisma.configChange.findMany({
      where:   { ...changeWhere, severity: { in: ['CRITICAL', 'HIGH'] } },
      orderBy: [{ severity: 'asc' }, { eventTime: 'desc' }],
      take:    50,
      select: {
        severity: true, category: true, eventName: true,
        resourceName: true, actor: true, eventTime: true, summary: true, freezeViolation: true,
      },
    });
  }

  if (schedule.sections.includes('DRIFT')) {
    const baselineWhere = schedule.provider && schedule.targetId
      ? { provider: schedule.provider, targetId: schedule.targetId, isActive: true }
      : { isActive: true };
    const baselines = await prisma.configBaseline.findMany({
      where:   baselineWhere,
      include: { driftResults: { where: { status: 'OPEN' }, take: 30 } },
    });
    data.driftResults = baselines.flatMap((b) =>
      b.driftResults.map((d) => ({
        baselineName:  b.name,
        driftType:     d.driftType,
        resourceType:  d.resourceType,
        resourceName:  d.resourceName,
        severity:      d.severity,
        driftedFields: (d.driftedFields ?? []) as string[],
      }))
    );
  }

  if (schedule.sections.includes('IAM_ESCALATION')) {
    const iamWhere = schedule.provider && schedule.targetId
      ? { provider: schedule.provider, targetId: schedule.targetId, eventTime: { gte: since30d } }
      : { eventTime: { gte: since30d } };
    data.iamEscalations = await prisma.iamEscalationEvent.findMany({
      where:   iamWhere,
      orderBy: { eventTime: 'desc' },
      take:    30,
      select: { escalationType: true, severity: true, actor: true, eventName: true, summary: true, eventTime: true, status: true },
    });
  }

  if (schedule.sections.includes('POSTURE')) {
    const postureWhere = schedule.provider && schedule.targetId
      ? { provider: schedule.provider, targetId: schedule.targetId }
      : {};
    // Latest score per target using raw approach
    const scores = await prisma.postureScore.findMany({
      where:   postureWhere,
      orderBy: { calculatedAt: 'desc' },
      take:    100,
      select:  { provider: true, targetId: true, score: true, grade: true, calculatedAt: true },
    });
    // Deduplicate by provider+targetId
    const seen = new Set<string>();
    data.postureScores = scores.filter((s) => {
      const k = `${s.provider}:${s.targetId}`;
      if (seen.has(k)) return false;
      seen.add(k); return true;
    });
  }

  return data;
}

// ─── HTML report generator ────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706', LOW: '#2563eb', INFO: '#6b7280',
};
const GRADE_COLOR: Record<string, string> = {
  A: '#16a34a', B: '#2563eb', C: '#d97706', D: '#ea580c', F: '#dc2626',
};

export function generateReportHtml(data: ReportData): string {
  const fmtDate = (d: Date | string) =>
    new Date(d).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });

  const sevBadge = (sev: string) =>
    `<span style="background:${SEV_COLOR[sev] ?? '#888'};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600">${sev}</span>`;

  const gradeBadge = (grade: string, score: number) =>
    `<span style="background:${GRADE_COLOR[grade] ?? '#888'};color:#fff;padding:2px 10px;border-radius:4px;font-size:14px;font-weight:700">${grade} ${score}</span>`;

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${data.title}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#111;background:#f8f9fa;padding:32px}
  .page{max-width:900px;margin:0 auto;background:#fff;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.08);overflow:hidden}
  .header{background:linear-gradient(135deg,#1e3a5f,#2563eb);color:#fff;padding:32px 40px}
  .header h1{font-size:24px;font-weight:700;margin-bottom:6px}
  .header p{opacity:.8;font-size:14px}
  .section{padding:28px 40px;border-bottom:1px solid #e5e7eb}
  .section:last-child{border-bottom:none}
  h2{font-size:16px;font-weight:700;color:#1e3a5f;margin-bottom:16px;display:flex;align-items:center;gap:8px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{background:#f1f5f9;text-align:left;padding:8px 12px;font-weight:600;color:#374151;border-bottom:2px solid #e2e8f0}
  td{padding:8px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top}
  tr:hover td{background:#fafbff}
  .stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:4px}
  .stat{background:#f8f9fa;border-radius:8px;padding:16px;text-align:center}
  .stat-val{font-size:28px;font-weight:700}
  .stat-lbl{font-size:12px;color:#6b7280;margin-top:4px}
  .critical{color:#dc2626}.high{color:#ea580c}.medium{color:#d97706}.low{color:#2563eb}
  .freeze-badge{background:#fef3c7;color:#92400e;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:600}
  .footer{background:#f8f9fa;padding:16px 40px;text-align:center;font-size:12px;color:#9ca3af}
  @media print{body{padding:0}  .page{box-shadow:none;border-radius:0}}
</style>
</head>
<body>
<div class="page">
<div class="header">
  <h1>${data.title}</h1>
  <p>Generated ${fmtDate(data.generatedAt)}${data.provider ? ` &nbsp;·&nbsp; ${data.provider}` : ''}</p>
</div>`;

  // SUMMARY
  if (data.summary) {
    html += `
<div class="section">
<h2>📊 Open Issues Summary (30 days)</h2>
<div class="stat-grid">
  <div class="stat"><div class="stat-val critical">${data.summary.critical}</div><div class="stat-lbl">Critical</div></div>
  <div class="stat"><div class="stat-val high">${data.summary.high}</div><div class="stat-lbl">High</div></div>
  <div class="stat"><div class="stat-val medium">${data.summary.medium}</div><div class="stat-lbl">Medium</div></div>
  <div class="stat"><div class="stat-val low">${data.summary.low}</div><div class="stat-lbl">Low</div></div>
</div>
</div>`;
  }

  // POSTURE
  if (data.postureScores && data.postureScores.length > 0) {
    html += `
<div class="section">
<h2>🛡 Risk Posture Scores</h2>
<table>
<thead><tr><th>Provider</th><th>Target</th><th>Score</th><th>Calculated</th></tr></thead>
<tbody>`;
    for (const s of data.postureScores) {
      html += `<tr><td>${s.provider}</td><td style="font-family:monospace;font-size:12px">${s.targetId.slice(0, 20)}…</td><td>${gradeBadge(s.grade, s.score)}</td><td>${fmtDate(s.calculatedAt)}</td></tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // CONFIG CHANGES
  if (data.configChanges && data.configChanges.length > 0) {
    html += `
<div class="section">
<h2>🔄 Critical &amp; High Config Changes (30 days)</h2>
<table>
<thead><tr><th>Severity</th><th>Event</th><th>Resource</th><th>Actor</th><th>Time</th></tr></thead>
<tbody>`;
    for (const c of data.configChanges) {
      html += `<tr>
        <td>${sevBadge(c.severity)}${c.freezeViolation ? ' <span class="freeze-badge">❄ FREEZE</span>' : ''}</td>
        <td style="font-size:12px">${c.eventName}</td>
        <td>${c.resourceName ?? '—'}</td>
        <td>${c.actor ?? '—'}</td>
        <td style="font-size:12px;white-space:nowrap">${fmtDate(c.eventTime)}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // DRIFT
  if (data.driftResults && data.driftResults.length > 0) {
    html += `
<div class="section">
<h2>📐 Configuration Drift</h2>
<table>
<thead><tr><th>Baseline</th><th>Type</th><th>Resource</th><th>Severity</th><th>Changed Fields</th></tr></thead>
<tbody>`;
    for (const d of data.driftResults) {
      const typeColor = d.driftType === 'ADDED' ? '#16a34a' : d.driftType === 'DELETED' ? '#dc2626' : '#d97706';
      html += `<tr>
        <td>${d.baselineName}</td>
        <td><span style="color:${typeColor};font-weight:600">${d.driftType}</span></td>
        <td>${d.resourceName ?? d.resourceType}</td>
        <td>${sevBadge(d.severity)}</td>
        <td style="font-size:11px;color:#6b7280">${d.driftedFields.slice(0, 4).join(', ')}${d.driftedFields.length > 4 ? ` +${d.driftedFields.length - 4}` : ''}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // IAM ESCALATION
  if (data.iamEscalations && data.iamEscalations.length > 0) {
    html += `
<div class="section">
<h2>⚠️ IAM Privilege Escalation Events (30 days)</h2>
<table>
<thead><tr><th>Severity</th><th>Type</th><th>Event</th><th>Actor</th><th>Status</th><th>Time</th></tr></thead>
<tbody>`;
    for (const e of data.iamEscalations) {
      html += `<tr>
        <td>${sevBadge(e.severity)}</td>
        <td style="font-size:12px">${e.escalationType.replace(/_/g, ' ')}</td>
        <td style="font-size:12px">${e.eventName}</td>
        <td>${e.actor ?? '—'}</td>
        <td><span style="color:${e.status === 'OPEN' ? '#dc2626' : '#16a34a'}">${e.status}</span></td>
        <td style="font-size:12px;white-space:nowrap">${fmtDate(e.eventTime)}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  html += `
<div class="footer">
  Generated by Cloud Scanner &nbsp;·&nbsp; ${fmtDate(data.generatedAt)}<br>
  This report is confidential and intended for authorized recipients only.
</div>
</div>
</body></html>`;

  return html;
}

// ─── Email delivery ───────────────────────────────────────────────────────────

async function emailReport(
  recipients: string[],
  title: string,
  html: string,
): Promise<void> {
  const transport = getTransport();
  await transport.sendMail({
    from:    process.env.REPORT_SMTP_FROM ?? 'scanner@noreply.local',
    to:      recipients.join(', '),
    subject: `[Cloud Scanner Report] ${title}`,
    html,
  });
}

// ─── Schedule processor ───────────────────────────────────────────────────────

/**
 * Called every minute from app.ts.
 * Checks for due report schedules and generates + delivers them.
 */
export async function processScheduledReports(): Promise<void> {
  const due = await prisma.reportSchedule.findMany({
    where: {
      isActive:    true,
      frequency:   { not: 'ON_DEMAND' },
      nextRunAt:   { lte: new Date() },
    },
  });

  await Promise.allSettled(
    due.map(async (schedule) => {
      const run = await prisma.reportRun.create({
        data: { scheduleId: schedule.id, status: 'RUNNING' },
      });

      try {
        const data = await gatherReportData(schedule);
        const html = generateReportHtml(data);

        if (schedule.recipients.length > 0) {
          await emailReport(schedule.recipients, schedule.name, html);
        }

        const nextRunAt = computeNextRun(
          schedule.frequency,
          schedule.hour,
          schedule.dayOfWeek,
          schedule.dayOfMonth,
        );

        await Promise.all([
          prisma.reportRun.update({
            where: { id: run.id },
            data:  { status: 'COMPLETED', completedAt: new Date() },
          }),
          prisma.reportSchedule.update({
            where: { id: schedule.id },
            data:  { lastRunAt: new Date(), nextRunAt },
          }),
        ]);

        logger.info(`[reports] Schedule "${schedule.name}" delivered to ${schedule.recipients.length} recipients`);
      } catch (err) {
        await Promise.all([
          prisma.reportRun.update({
            where: { id: run.id },
            data:  { status: 'FAILED', completedAt: new Date(), errorMessage: (err as Error).message.slice(0, 500) },
          }),
          prisma.reportSchedule.update({
            where: { id: schedule.id },
            data:  { lastRunAt: new Date() },
          }),
        ]);
        logger.warn(`[reports] Schedule "${schedule.name}" failed: ${(err as Error).message}`);
      }
    }),
  );
}

/**
 * On-demand report generation — returns the HTML string directly.
 */
export async function generateOnDemandReport(scheduleId: string): Promise<string> {
  const schedule = await prisma.reportSchedule.findUnique({ where: { id: scheduleId } });
  if (!schedule) throw new Error('Schedule not found');

  const data = await gatherReportData(schedule);
  const html = generateReportHtml(data);

  await prisma.reportRun.create({
    data: { scheduleId: schedule.id, status: 'COMPLETED', completedAt: new Date() },
  });

  return html;
}
