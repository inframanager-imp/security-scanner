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
import puppeteer        from 'puppeteer-core';
import { prisma }       from '../config/database';
import { logger }       from '../config/logger';
import { scoreFrameworks } from './complianceService';

// ─── Real PDF rendering (server-side, headless Chrome) ─────────────────────────

export async function renderHtmlToPdf(html: string): Promise<Buffer> {
  const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium';
  const browser = await puppeteer.launch({
    executablePath,
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
  });
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    const pdf = await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: { top: '0', bottom: '0', left: '0', right: '0' },
    });
    return Buffer.from(pdf);
  } finally {
    await browser.close();
  }
}

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
  findingsSummary?: { critical: number; high: number; medium: number; low: number; info: number; total: number };
  topFindings?: Array<{ provider: string; severity: string; service: string; title: string; discoveredAt: Date }>;
  configChanges?: Array<{ severity: string; category: string; eventName: string; resourceName: string | null; actor: string | null; eventTime: Date; summary: string; freezeViolation: boolean }>;
  driftResults?: Array<{ baselineName: string; driftType: string; resourceType: string; resourceName: string | null; severity: string; driftedFields: string[] }>;
  iamEscalations?: Array<{ escalationType: string; severity: string; actor: string | null; eventName: string; summary: string; eventTime: Date; status: string }>;
  postureScores?: Array<{ provider: string; targetId: string; score: number; grade: string; calculatedAt: Date }>;
}

// ─── Real findings gatherer (Finding / AzureFinding / GcpFinding) ─────────────

async function gatherFindingsSummary(
  provider: string | null,
  targetId: string | null,
): Promise<{ summary: ReportData['findingsSummary']; top: NonNullable<ReportData['topFindings']> }> {
  const zero = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  const counts = { ...zero };
  const top: NonNullable<ReportData['topFindings']> = [];

  const bump = (sev: string, n: number) => {
    const key = sev.toLowerCase() as keyof typeof zero;
    if (key in counts) counts[key] += n;
    counts.total += n;
  };

  if (!provider || provider === 'AWS') {
    const where = targetId && provider === 'AWS'
      ? { findingStatus: 'OPEN' as const, scan: { account: { awsAccountId: targetId } } }
      : { findingStatus: 'OPEN' as const };
    const bySev = await prisma.finding.groupBy({ by: ['severity'], where, _count: { id: true } });
    for (const r of bySev) bump(r.severity, r._count.id);
    const rows = await prisma.finding.findMany({
      where, orderBy: [{ severity: 'asc' }, { discoveredAt: 'desc' }], take: 25,
      select: { severity: true, service: true, title: true, discoveredAt: true },
    });
    top.push(...rows.map((r) => ({ provider: 'AWS', severity: r.severity, service: r.service, title: r.title, discoveredAt: r.discoveredAt })));
  }

  if (!provider || provider === 'AZURE') {
    const where = targetId && provider === 'AZURE'
      ? { findingStatus: 'OPEN' as const, scan: { subscription: { subscriptionId: targetId } } }
      : { findingStatus: 'OPEN' as const };
    const bySev = await prisma.azureFinding.groupBy({ by: ['severity'], where, _count: { id: true } });
    for (const r of bySev) bump(r.severity, r._count.id);
    if (provider === 'AZURE') {
      const rows = await prisma.azureFinding.findMany({
        where, orderBy: [{ severity: 'asc' }, { discoveredAt: 'desc' }], take: 25,
        select: { severity: true, service: true, title: true, discoveredAt: true },
      });
      top.push(...rows.map((r) => ({ provider: 'AZURE', severity: r.severity, service: r.service, title: r.title, discoveredAt: r.discoveredAt })));
    }
  }

  if (!provider || provider === 'GCP') {
    const where = targetId && provider === 'GCP'
      ? { findingStatus: 'OPEN' as const, scan: { project: { projectId: targetId } } }
      : { findingStatus: 'OPEN' as const };
    const bySev = await prisma.gcpFinding.groupBy({ by: ['severity'], where, _count: { id: true } });
    for (const r of bySev) bump(r.severity, r._count.id);
    if (provider === 'GCP') {
      const rows = await prisma.gcpFinding.findMany({
        where, orderBy: [{ severity: 'asc' }, { discoveredAt: 'desc' }], take: 25,
        select: { severity: true, service: true, title: true, discoveredAt: true },
      });
      top.push(...rows.map((r) => ({ provider: 'GCP', severity: r.severity, service: r.service, title: r.title, discoveredAt: r.discoveredAt })));
    }
  }

  top.sort((a, b) => a.severity.localeCompare(b.severity) || b.discoveredAt.getTime() - a.discoveredAt.getTime());
  return { summary: counts, top: top.slice(0, 25) };
}

// ─── Executive Report (ad-hoc /compile) ────────────────────────────────────────

function letterGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

export interface ExecutiveAccountReport {
  id: string;
  name: string;
  awsAccountId: string;
  lastScanAt: Date | null;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  summary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
  byService: Array<{ service: string; critical: number; high: number; total: number }>;
  topFindings: Array<{ severity: string; service: string; title: string; remediation: string }>;
}

export interface ExecutiveReportData {
  title: string;
  scopeLabel: string;
  generatedAt: string;
  accounts: ExecutiveAccountReport[];
  overallGrade: 'A' | 'B' | 'C' | 'D' | 'F';
  overallSummary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
  frameworks: ReturnType<typeof scoreFrameworks>;
}

export async function gatherExecutiveReportData(targetId: string | null): Promise<ExecutiveReportData> {
  const accountRows = await prisma.account.findMany({
    where: targetId ? { awsAccountId: targetId } : undefined,
    select: { id: true, name: true, awsAccountId: true },
    orderBy: { name: 'asc' },
  });

  const overallSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  const allTitles = new Set<string>();
  const allCounts = new Map<string, number>();
  const allCheckIds = new Set<string>();
  const allCheckIdCounts = new Map<string, number>();

  const accounts: ExecutiveAccountReport[] = await Promise.all(accountRows.map(async (acct) => {
    const [lastScan, findings] = await Promise.all([
      prisma.scan.findFirst({ where: { accountId: acct.id, status: 'COMPLETED' }, orderBy: { completedAt: 'desc' }, select: { completedAt: true } }),
      prisma.finding.findMany({
        where: { findingStatus: { in: ['OPEN', 'ACKNOWLEDGED'] }, scan: { accountId: acct.id } },
        select: { severity: true, service: true, title: true, checkId: true, remediation: true, discoveredAt: true },
      }),
    ]);

    const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    const byServiceMap = new Map<string, { critical: number; high: number; total: number }>();
    for (const f of findings) {
      const key = f.severity.toLowerCase() as keyof typeof summary;
      if (key in summary && key !== 'total') summary[key] += 1;
      summary.total += 1;

      const svc = byServiceMap.get(f.service) ?? { critical: 0, high: 0, total: 0 };
      if (f.severity === 'CRITICAL') svc.critical += 1;
      if (f.severity === 'HIGH') svc.high += 1;
      svc.total += 1;
      byServiceMap.set(f.service, svc);

      if (f.checkId) {
        allCheckIds.add(f.checkId);
        allCheckIdCounts.set(f.checkId, (allCheckIdCounts.get(f.checkId) ?? 0) + 1);
      } else {
        allTitles.add(f.title);
        allCounts.set(f.title, (allCounts.get(f.title) ?? 0) + 1);
      }
    }
    (Object.keys(overallSummary) as Array<keyof typeof overallSummary>).forEach((k) => { overallSummary[k] += summary[k]; });

    const topFindings = findings
      .filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
      .sort((a, b) => a.severity.localeCompare(b.severity) || b.discoveredAt.getTime() - a.discoveredAt.getTime())
      .slice(0, 15)
      .map((f) => ({ severity: f.severity, service: f.service, title: f.title, remediation: f.remediation }));

    const penalty = Math.min(summary.critical, 3) * 15 + Math.min(summary.high, 4) * 8 + Math.min(summary.medium, 5) * 3 + Math.min(summary.low, 5) * 1;
    const score = Math.max(0, 100 - penalty);

    return {
      id: acct.id, name: acct.name, awsAccountId: acct.awsAccountId,
      lastScanAt: lastScan?.completedAt ?? null,
      grade: letterGrade(score),
      summary,
      byService: [...byServiceMap.entries()].map(([service, v]) => ({ service, ...v })).sort((a, b) => b.total - a.total),
      topFindings,
    };
  }));

  const overallPenalty = Math.min(overallSummary.critical, 3) * 15 + Math.min(overallSummary.high, 4) * 8 + Math.min(overallSummary.medium, 5) * 3 + Math.min(overallSummary.low, 5) * 1;
  const frameworks = scoreFrameworks(allTitles, allCounts, allCheckIds, allCheckIdCounts);

  return {
    title: targetId && accounts[0] ? accounts[0].name : 'All Accounts',
    scopeLabel: targetId && accounts[0] ? accounts[0].name : 'All Accounts',
    generatedAt: new Date().toISOString(),
    accounts,
    overallGrade: letterGrade(Math.max(0, 100 - overallPenalty)),
    overallSummary,
    frameworks,
  };
}

const SEV_BADGE_COLOR: Record<string, string> = { CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706', LOW: '#2563eb', INFO: '#6b7280' };
const GRADE_BOX_COLOR: Record<string, string> = { A: '#16a34a', B: '#2563eb', C: '#d97706', D: '#ea580c', F: '#dc2626' };

function sevBar(label: string, value: number, max: number, color: string): string {
  const pct = max > 0 ? Math.max(2, Math.round((value / max) * 100)) : 2;
  return `
<div style="display:flex;align-items:center;gap:16px;margin-bottom:14px">
  <div style="width:90px;font-weight:700;font-size:13px;color:#1e293b">${label}</div>
  <div style="flex:1;background:#eef1f5;border-radius:4px;height:34px;overflow:hidden">
    <div style="width:${pct}%;background:${color};height:100%"></div>
  </div>
  <div style="width:36px;text-align:right;font-weight:700;font-size:16px;color:#1e293b">${value}</div>
</div>`;
}

export function generateExecutiveReportHtml(data: ExecutiveReportData): string {
  const fmtDate = (d: Date | string | null) => d ? new Date(d).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' }) : 'Never';
  const s = data.overallSummary;
  const maxSev = Math.max(s.critical, s.high, s.medium, s.low, s.info, 1);

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${data.title} — Cloud Security Posture Assessment</title>
<style>
  body{font-family:-apple-system,'Segoe UI',Roboto,sans-serif;margin:0;background:#f3f4f6;color:#1e293b}
  .page{max-width:1000px;margin:0 auto;background:#fff}
  .header{background:linear-gradient(135deg,#0f2f66,#1d4ed8);color:#fff;padding:40px}
  .tag{display:inline-block;background:rgba(255,255,255,0.15);padding:6px 14px;border-radius:4px;font-size:11px;letter-spacing:1.5px;font-weight:700;text-transform:uppercase;margin-bottom:20px}
  .header h1{margin:0 0 6px;font-size:40px}
  .header .sub{opacity:.85;margin:0 0 24px}
  .meta-row{display:flex;justify-content:space-between;border-top:1px solid rgba(255,255,255,.2);padding-top:20px;margin-bottom:24px}
  .meta-col p{margin:0}
  .meta-lbl{font-size:11px;letter-spacing:1px;text-transform:uppercase;opacity:.7;margin-bottom:4px !important}
  .meta-val{font-size:18px;font-weight:700}
  .stat-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
  .stat{background:rgba(255,255,255,.12);border-radius:8px;padding:16px;text-align:center}
  .stat-val{font-size:26px;font-weight:800}
  .stat-lbl{font-size:11px;letter-spacing:1px;text-transform:uppercase;opacity:.8;margin-top:2px}
  .body{padding:32px 40px}
  .section{margin-bottom:36px}
  .section h2{font-size:19px;border-bottom:2px solid #e2e8f0;padding-bottom:10px;margin-bottom:16px}
  .section h2 .num{color:#2563eb}
  .section h3{font-size:15px;margin:20px 0 10px}
  table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:8px}
  th{background:#0f2f66;color:#fff;text-align:left;padding:10px 12px;font-weight:600;font-size:11px;letter-spacing:.5px;text-transform:uppercase}
  td{padding:9px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top}
  tr:hover td{background:#fafbff}
  .pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;background:#f1f5f9;font-size:12px;font-weight:600;margin-right:8px}
  .dot{width:8px;height:8px;border-radius:50%}
  .grade-box{width:150px;height:150px;border:3px solid #16a34a;border-radius:12px;display:flex;flex-direction:column;align-items:center;justify-content:center;flex-shrink:0}
  .grade-box .letter{font-size:56px;font-weight:800}
  .grade-box .lbl{font-size:11px;letter-spacing:1px;text-transform:uppercase;color:#6b7280;margin-top:4px;text-align:center}
  .compliance-bar{width:120px;background:#eef1f5;border-radius:4px;height:8px;overflow:hidden;display:inline-block;vertical-align:middle}
  .compliance-bar .fill{height:100%}
  .badge{color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}
  .footer{background:#f8f9fa;padding:20px 40px;text-align:center;font-size:12px;color:#9ca3af}
  @media print{body{padding:0;background:#fff} .page{box-shadow:none} .section{page-break-inside:avoid}}
</style>
</head>
<body>
<div class="page">

<div class="header">
  <div class="tag">Cloud Security Posture · Executive Report</div>
  <h1>${data.title}</h1>
  <p class="sub">Cloud Security Posture Assessment</p>
  <div class="meta-row">
    <div class="meta-col">
      <p class="meta-lbl">Scope</p><p class="meta-val">${data.scopeLabel}</p>
      <p class="meta-lbl" style="margin-top:10px">Generated</p><p class="meta-val">${new Date(data.generatedAt).toISOString().slice(0, 16).replace('T', ' ')} UTC</p>
    </div>
    <div class="meta-col" style="text-align:right">
      <p class="meta-lbl">Accounts</p><p class="meta-val">${data.accounts.length}</p>
      <p class="meta-lbl" style="margin-top:10px">Overall Grade</p><p class="meta-val">${data.overallGrade}</p>
    </div>
  </div>
  <div class="stat-grid">
    <div class="stat"><div class="stat-val">${s.critical}</div><div class="stat-lbl">Critical</div></div>
    <div class="stat"><div class="stat-val">${s.high}</div><div class="stat-lbl">High</div></div>
    <div class="stat"><div class="stat-val">${s.medium}</div><div class="stat-lbl">Medium</div></div>
    <div class="stat"><div class="stat-val">${s.low}</div><div class="stat-lbl">Low</div></div>
    <div class="stat"><div class="stat-val">${s.info}</div><div class="stat-lbl">Info</div></div>
  </div>
</div>

<div class="body">

<div class="section">
<h2><span class="num">1.</span> Executive Summary</h2>
<div style="display:flex;gap:28px;align-items:flex-start">
  <div class="grade-box" style="border-color:${GRADE_BOX_COLOR[data.overallGrade]}">
    <div class="letter" style="color:${GRADE_BOX_COLOR[data.overallGrade]}">${data.overallGrade}</div>
    <div class="lbl">Overall<br>Grade</div>
  </div>
  <div style="flex:1">
    <p>This report summarises the current cloud security posture across ${data.accounts.length} account(s), covering ${s.total} open findings from the most recent completed scan of each account.</p>
    <div style="margin:14px 0 22px">
      ${(['critical', 'high', 'medium', 'low', 'info'] as const).map((k) => `<span class="pill"><span class="dot" style="background:${SEV_BADGE_COLOR[k.toUpperCase()]}"></span>${k.toUpperCase()} ${s[k]}</span>`).join('')}
    </div>
  </div>
</div>
${(['critical', 'high', 'medium', 'low', 'info'] as const).map((k) => sevBar(k.toUpperCase(), s[k], maxSev, SEV_BADGE_COLOR[k.toUpperCase()])).join('')}
</div>

<div class="section">
<h2><span class="num">2.</span> Compliance Framework Overview</h2>
<p style="color:#6b7280;font-size:13px;margin-top:-8px">Control coverage across major frameworks, derived from open &amp; acknowledged findings. Not-evaluated controls are excluded from the score.</p>
<table>
<thead><tr><th>Framework</th><th>Score</th><th>Passed</th><th>Failed</th><th>N/A</th><th>Compliance</th></tr></thead>
<tbody>
${data.frameworks.map((fw) => `<tr>
  <td><strong>${fw.shortName}</strong><br><span style="color:#9ca3af;font-size:11px">${fw.frameworkName}</span></td>
  <td style="font-weight:700;color:${fw.score >= 70 ? '#16a34a' : fw.score >= 40 ? '#d97706' : '#dc2626'}">${fw.score}%</td>
  <td style="color:#16a34a">${fw.passingControls}</td>
  <td style="color:#dc2626">${fw.failingControls}</td>
  <td style="color:#9ca3af">${fw.notEvaluatedControls}</td>
  <td><span class="compliance-bar"><span class="fill" style="width:${fw.score}%;background:${fw.score >= 70 ? '#16a34a' : fw.score >= 40 ? '#d97706' : '#dc2626'}"></span></span></td>
</tr>`).join('')}
</tbody>
</table>
</div>

<div class="section">
<h2><span class="num">3.</span> Accounts Overview</h2>
<table>
<thead><tr><th>Account</th><th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Total</th><th>Last Scan</th></tr></thead>
<tbody>
${data.accounts.map((a) => `<tr>
  <td><strong>${a.name}</strong><br><span style="color:#9ca3af;font-size:11px;font-family:monospace">${a.awsAccountId}</span></td>
  <td style="color:#dc2626">${a.summary.critical}</td>
  <td style="color:#ea580c">${a.summary.high}</td>
  <td style="color:#d97706">${a.summary.medium}</td>
  <td style="color:#2563eb">${a.summary.low}</td>
  <td style="font-weight:700">${a.summary.total}</td>
  <td style="font-size:12px">${fmtDate(a.lastScanAt)}</td>
</tr>`).join('')}
</tbody>
</table>
</div>

<div class="section">
<h2><span class="num">4.</span> Account Detail</h2>
${data.accounts.map((a, i) => {
  const maxA = Math.max(a.summary.critical, a.summary.high, a.summary.medium, a.summary.low, a.summary.info, 1);
  return `
<h3>${i + 1}. ${a.name} <span style="color:#9ca3af;font-weight:400;font-family:monospace">(${a.awsAccountId})</span></h3>
<p style="color:#6b7280;font-size:13px;margin-top:-6px">Grade <strong style="color:${GRADE_BOX_COLOR[a.grade]}">${a.grade}</strong> · ${a.summary.total} open findings · last scan ${fmtDate(a.lastScanAt)}</p>
${(['critical', 'high', 'medium', 'low', 'info'] as const).map((k) => sevBar(k.toUpperCase(), a.summary[k], maxA, SEV_BADGE_COLOR[k.toUpperCase()])).join('')}
${a.byService.length > 0 ? `
<h3>Findings by Service</h3>
<table>
<thead><tr><th>Service</th><th>Critical</th><th>High</th><th>Total</th></tr></thead>
<tbody>${a.byService.map((sv) => `<tr><td>${sv.service}</td><td style="color:#dc2626">${sv.critical}</td><td style="color:#ea580c">${sv.high}</td><td style="font-weight:700">${sv.total}</td></tr>`).join('')}</tbody>
</table>` : ''}
<h3>Top Critical &amp; High Findings</h3>
${a.topFindings.length > 0 ? `
<table>
<thead><tr><th>Severity</th><th>Service</th><th>Finding &amp; Remediation</th></tr></thead>
<tbody>${a.topFindings.map((f) => `<tr>
  <td><span class="badge" style="background:${SEV_BADGE_COLOR[f.severity]}">${f.severity}</span></td>
  <td>${f.service}</td>
  <td><strong>${f.title}</strong><br><span style="color:#6b7280;font-size:12px">${f.remediation}</span></td>
</tr>`).join('')}</tbody>
</table>` : '<p style="color:#9ca3af;font-size:13px">No critical or high findings.</p>'}
`;
}).join('<hr style="border:none;border-top:1px solid #e2e8f0;margin:28px 0">')}
</div>

</div>
<div class="footer">Generated by Cloud Scanner &middot; ${fmtDate(data.generatedAt)}<br>This report is confidential and intended for authorized recipients only.</div>
</div>
</body>
</html>`;

  return html;
}

export async function gatherReportData(schedule: {
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

  const findings = await gatherFindingsSummary(schedule.provider, schedule.targetId);
  data.findingsSummary = findings.summary;
  data.topFindings = findings.top;

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

  // FINDINGS SUMMARY (real open vulnerability findings — Finding/AzureFinding/GcpFinding)
  if (data.findingsSummary) {
    html += `
<div class="section">
<h2>Open Vulnerability Findings</h2>
<div class="stat-grid">
  <div class="stat"><div class="stat-val critical">${data.findingsSummary.critical}</div><div class="stat-lbl">Critical</div></div>
  <div class="stat"><div class="stat-val high">${data.findingsSummary.high}</div><div class="stat-lbl">High</div></div>
  <div class="stat"><div class="stat-val medium">${data.findingsSummary.medium}</div><div class="stat-lbl">Medium</div></div>
  <div class="stat"><div class="stat-val low">${data.findingsSummary.low}</div><div class="stat-lbl">Low</div></div>
</div>
</div>`;
  }

  if (data.topFindings && data.topFindings.length > 0) {
    html += `
<div class="section">
<h2>Top Open Findings</h2>
<table>
<thead><tr><th>Severity</th><th>Provider</th><th>Service</th><th>Finding</th><th>Discovered</th></tr></thead>
<tbody>`;
    for (const f of data.topFindings) {
      html += `<tr><td>${sevBadge(f.severity)}</td><td>${f.provider}</td><td>${f.service}</td><td>${f.title}</td><td>${fmtDate(f.discoveredAt)}</td></tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // SUMMARY (config CHANGE counts — distinct from findings above)
  if (data.summary) {
    html += `
<div class="section">
<h2>Open Config Changes Summary (30 days)</h2>
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
<h2>Risk Posture Scores</h2>
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
<h2>Critical &amp; High Config Changes (30 days)</h2>
<table>
<thead><tr><th>Severity</th><th>Event</th><th>Resource</th><th>Actor</th><th>Time</th></tr></thead>
<tbody>`;
    for (const c of data.configChanges) {
      html += `<tr>
        <td>${sevBadge(c.severity)}${c.freezeViolation ? ' <span class="freeze-badge">FREEZE</span>' : ''}</td>
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
<h2>Configuration Drift</h2>
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
<h2>IAM Privilege Escalation Events (30 days)</h2>
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
