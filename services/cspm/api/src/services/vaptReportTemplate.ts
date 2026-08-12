/**
 * Renders a VaptReportModel (see vaptReportService.ts) into a single,
 * self-contained, print-ready HTML document — cover section, executive
 * summary, the Framework Score Overview (server-rendered SVG gauges,
 * matching the web app's Compliance/Reports tab visual language 1:1),
 * and the full findings list grouped by severity with remediation guidance.
 *
 * No client JS, no external assets — this needs to render identically when
 * opened in a new tab AND when printed/saved as PDF via the browser's print
 * dialog. Layout is tuned for that: `@page` sizing + `break-inside: avoid`
 * on every card/row so a finding never gets visually split across pages.
 */

import type { VaptReportModel, VaptFinding, VaptFrameworkScoreSummary, VaptIamUser } from './vaptReportService';

// ─── Shared palette (kept in sync with the frontend's severity/score colors) ──

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#b91c1c', HIGH: '#ea580c', MEDIUM: '#d97706', LOW: '#2563eb', INFO: '#64748b',
};
const PROVIDER_META: Record<VaptReportModel['provider'], { label: string; color: string }> = {
  AWS:   { label: 'Amazon Web Services', color: '#c2410c' },
  AZURE: { label: 'Microsoft Azure',     color: '#1d4ed8' },
  GCP:   { label: 'Google Cloud Platform', color: '#15803d' },
};
const RATING_COLOR: Record<VaptReportModel['riskRating'], string> = {
  CRITICAL: '#b91c1c', HIGH: '#ea580c', MODERATE: '#d97706', LOW: '#16a34a',
};

function gaugeColor(score: number): string {
  if (score >= 80) return '#10b981';
  if (score >= 60) return '#f59e0b';
  return '#ef4444';
}

// ─── Escaping ──────────────────────────────────────────────────────────────
// Findings/evidence ultimately derive from scanned cloud resources (names,
// tags, etc. an account owner controls) — escape everything interpolated
// into the document so a crafted resource name can't inject markup.

function esc(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function fmtDateTime(d: Date | string): string {
  return new Date(d).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
}
function fmtDate(d: Date | string): string {
  return new Date(d).toLocaleDateString('en-US', { dateStyle: 'long' });
}

// ─── SVG gauge (mirrors web/src/components/ui/FrameworkScoreOverview.tsx) ────

function svgGauge(score: number, label: string, sublabel: string): string {
  const size = 96, r = 36, circ = 2 * Math.PI * r, offset = circ * (1 - score / 100);
  const color = gaugeColor(score);
  return `
    <div class="gauge">
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
        <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="#e5e7eb" stroke-width="8"/>
        <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${color}" stroke-width="8"
          stroke-dasharray="${circ}" stroke-dashoffset="${offset}" stroke-linecap="round"
          transform="rotate(-90 ${size / 2} ${size / 2})"/>
        <text x="${size / 2}" y="${size / 2 + 5}" text-anchor="middle" font-size="16" font-weight="700" fill="${color}">${score}%</text>
      </svg>
      <p class="gauge-label">${esc(label)}</p>
      <p class="gauge-sublabel">${esc(sublabel)}</p>
    </div>`;
}

// ─── Sections ─────────────────────────────────────────────────────────────

function filtersBanner(model: VaptReportModel): string {
  const f = model.appliedFilters;
  const parts: string[] = [];
  if (f.tags.length)          parts.push(`Tags: ${f.tags.map(esc).join(', ')}`);
  if (f.region.length)        parts.push(`Region: ${f.region.map(esc).join(', ')}`);
  if (f.resourceGroup.length) parts.push(`Resource Group: ${f.resourceGroup.map(esc).join(', ')}`);
  if (parts.length === 0) return '';
  return `
  <div class="cover-filters">
    <span class="cover-filters-label">FILTERED REPORT — does not cover the full target</span>
    <span class="cover-filters-val">${parts.join(' &nbsp;&middot;&nbsp; ')}</span>
  </div>`;
}

function coverSection(model: VaptReportModel): string {
  const meta = PROVIDER_META[model.provider];
  const ratingColor = RATING_COLOR[model.riskRating];
  return `
<div class="cover">
  <div class="cover-badge" style="background:${meta.color}">${esc(meta.label)}</div>
  <h1>VAPT Security Assessment Report</h1>
  <p class="cover-target">${esc(model.targetName)}</p>
  <p class="cover-id">${esc(model.provider)} ID: <span class="mono">${esc(model.targetExternalId)}</span></p>
  <div class="cover-meta">
    <div><span class="cover-meta-label">Generated</span><span class="cover-meta-val">${fmtDateTime(model.generatedAt)}</span></div>
    <div><span class="cover-meta-label">Last Scan</span><span class="cover-meta-val">${model.lastScanAt ? fmtDateTime(model.lastScanAt) : 'No completed scan yet'}</span></div>
    <div><span class="cover-meta-label">Overall Risk Rating</span><span class="cover-meta-val" style="color:${ratingColor};font-weight:800">${model.riskRating}</span></div>
  </div>
  ${filtersBanner(model)}
  <p class="cover-confidential">CONFIDENTIAL — Prepared for authorized recipients only. Distribution outside the intended audience is prohibited.</p>
</div>`;
}

function execSummarySection(model: VaptReportModel): string {
  const s = model.summary;
  const stat = (label: string, value: number, cls = '') =>
    `<div class="stat"><div class="stat-val ${cls}">${value}</div><div class="stat-lbl">${esc(label)}</div></div>`;
  return `
<div class="section">
  <h2>Executive Summary</h2>
  <div class="stat-grid">
    ${stat('Critical', s.critical, 'critical')}
    ${stat('High', s.high, 'high')}
    ${stat('Medium', s.medium, 'medium')}
    ${stat('Low', s.low, 'low')}
    ${stat('Info', s.info, 'info')}
    ${stat('Total Open Findings', s.total)}
  </div>
  <p class="exec-narrative">
    This assessment identified <strong>${s.total}</strong> open finding${s.total === 1 ? '' : 's'} across
    <strong>${esc(model.targetName)}</strong> (${esc(model.provider)}), yielding a composite risk score of
    <strong>${model.riskScore}</strong> — rated <strong style="color:${RATING_COLOR[model.riskRating]}">${model.riskRating}</strong>.
    ${s.critical > 0 ? `<strong>${s.critical} critical-severity finding${s.critical === 1 ? '' : 's'}</strong> require immediate remediation. ` : ''}
    ${s.high > 0 ? `<strong>${s.high} high-severity finding${s.high === 1 ? '' : 's'}</strong> should be prioritized in the current remediation cycle.` : ''}
  </p>
</div>`;
}

function frameworkSection(scores: VaptFrameworkScoreSummary[] | null): string {
  if (!scores || scores.length === 0) {
    return `
<div class="section">
  <h2>Compliance Framework Score Overview</h2>
  <p class="muted">Compliance framework scoring is not yet available for this cloud provider.</p>
</div>`;
  }
  const gauges = scores.map(f => svgGauge(f.score, f.shortName, `${f.passingControls}/${f.totalControls} controls`)).join('');
  const rows = scores.map(f => `
    <tr>
      <td>${esc(f.frameworkName)}</td>
      <td class="num">${f.passingControls}</td>
      <td class="num">${f.failingControls}</td>
      <td class="num">${f.notEvaluatedControls}</td>
      <td class="num" style="color:${gaugeColor(f.score)};font-weight:700">${f.score}%</td>
    </tr>`).join('');
  return `
<div class="section">
  <h2>Compliance Framework Score Overview</h2>
  <div class="gauge-grid">${gauges}</div>
  <table>
    <thead><tr><th>Framework</th><th class="num">Passing</th><th class="num">Failing</th><th class="num">Not Evaluated</th><th class="num">Score</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
</div>`;
}

// ─── IAM Users (AWS only — mirrors web/src/components/ui/IamUsersTable.tsx) ──

function policyChip(label: string, isAdmin: boolean): string {
  return `<span class="policy-chip${isAdmin ? ' policy-chip-admin' : ''}">${esc(label)}${isAdmin ? ' (full admin)' : ''}</span>`;
}

function iamUserRow(u: VaptIamUser): string {
  const policies = [
    ...u.directPolicies.map(p => policyChip(p.name, p.isAdminEquivalent)),
    ...u.groupPolicies.map(p => policyChip(`${p.policyName} (via ${p.groupName})`, p.isAdminEquivalent)),
  ].join('') || '<span class="muted">none</span>';
  const roles = u.assumableRoles
    .map(r => policyChip(`${r.roleName}${r.assumableBy === 'wildcard' ? ' (assumable by anyone)' : ''}`, r.isAdminEquivalent))
    .join('') || '<span class="muted">none</span>';
  const groups = u.groups.length > 0 ? esc(u.groups.join(', ')) : '<span class="muted">none</span>';

  const passwordCell = !u.passwordEnabled
    ? '<span class="muted">no console access</span>'
    : `<span${u.passwordStale ? ' class="stale-val"' : ''}>${u.passwordAgeDays ?? '—'}d ago</span>`;
  const keyCell = u.accessKeysActive === 0
    ? '<span class="muted">no active keys</span>'
    : u.hasNeverUsedActiveKey
      ? '<span class="stale-val">never used</span>'
      : `<span${u.keyStale ? ' class="stale-val"' : ''}>${u.accessKeyAgeDays ?? '—'}d ago</span>`;

  return `
<tr class="${u.hasOpenEndedAccess ? 'iam-row-flagged' : ''}">
  <td class="iam-user-cell">${esc(u.userName)}</td>
  <td>${u.hasOpenEndedAccess ? '<span class="open-ended-badge">Open-ended (admin)</span>' : '<span class="muted">Scoped</span>'}</td>
  <td>${u.mfaEnabled ? '<span class="ok-val">Enabled</span>' : '<span class="stale-val">Not enabled</span>'}</td>
  <td>${passwordCell}</td>
  <td>${keyCell}</td>
  <td class="iam-detail-cell">
    <div><strong>Groups:</strong> ${groups}</div>
    <div><strong>Policies:</strong> ${policies}</div>
    <div><strong>Assumable roles:</strong> ${roles}</div>
  </td>
</tr>`;
}

function iamUsersSection(model: VaptReportModel): string {
  if (model.iamUsers === null) return ''; // not available for this provider (Azure/GCP)
  if (model.iamUsers.length === 0) {
    return `
<div class="section">
  <h2>IAM Users</h2>
  <p class="muted">No IAM users found for this account.</p>
</div>`;
  }
  const openEndedCount = model.iamUsers.filter(u => u.hasOpenEndedAccess).length;
  const hygieneCount = model.iamUsers.filter(u => !u.mfaEnabled || u.passwordStale || u.keyStale).length;
  const rows = model.iamUsers.map(iamUserRow).join('');
  return `
<div class="section">
  <h2>IAM Users</h2>
  <p class="exec-narrative" style="margin-top:0;margin-bottom:14px">
    Effective permissions, assumable roles, and access hygiene per user.
    ${openEndedCount > 0 ? `<strong style="color:${SEV_COLOR.HIGH}">${openEndedCount} user${openEndedCount === 1 ? '' : 's'} with open-ended (admin-equivalent) access.</strong> ` : ''}
    ${hygieneCount > 0 ? `<strong style="color:${SEV_COLOR.MEDIUM}">${hygieneCount} user${hygieneCount === 1 ? '' : 's'} with an MFA, password, or access-key hygiene issue.</strong>` : ''}
  </p>
  <table>
    <thead><tr><th>User</th><th>Access Level</th><th>MFA</th><th>Password Changed</th><th>Access Key Last Used</th><th>Groups / Policies / Roles</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
</div>`;
}

function findingCard(f: VaptFinding): string {
  const color = SEV_COLOR[f.severity] ?? '#64748b';
  const complianceBadges = f.complianceTags.map(t => `<span class="compliance-chip">${esc(t)}</span>`).join('');
  return `
<div class="finding-card" style="border-left-color:${color}">
  <div class="finding-head">
    <span class="sev-badge" style="background:${color}">${esc(f.severity)}</span>
    <span class="finding-title">${esc(f.title)}</span>
    <span class="finding-service">${esc(f.service.toUpperCase())}</span>
    ${complianceBadges}
  </div>
  ${f.resourceName ? `<div class="finding-resource">Resource: <span class="mono">${esc(f.resourceName)}</span></div>` : ''}
  <div class="finding-body">
    <div>
      <h4>Description</h4>
      <p>${esc(f.description)}</p>
    </div>
    <div>
      <h4>Remediation</h4>
      <p>${esc(f.remediation)}</p>
    </div>
  </div>
  <div class="finding-foot">Discovered ${fmtDate(f.discoveredAt)}</div>
</div>`;
}

function findingsSection(model: VaptReportModel): string {
  if (model.findings.length === 0) {
    return `
<div class="section">
  <h2>Detailed Findings</h2>
  <p class="muted">No open findings — this target is currently clean.</p>
</div>`;
  }

  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const groups = order
    .map(sev => ({ sev, items: model.findings.filter(f => f.severity === sev) }))
    .filter(g => g.items.length > 0);

  const groupsHtml = groups.map(g => `
    <div class="severity-group">
      <h3 style="color:${SEV_COLOR[g.sev]}">${g.sev} <span class="count">(${g.items.length})</span></h3>
      ${g.items.map(findingCard).join('')}
    </div>`).join('');

  const truncNote = model.findingsTruncated
    ? `<p class="muted">Showing ${model.findings.length} of ${model.findingsTotalCount} open findings. Export the full list from Operations &rarr; Reports for the complete set.</p>`
    : '';

  return `
<div class="section">
  <h2>Detailed Findings</h2>
  ${truncNote}
  ${groupsHtml}
</div>`;
}

// ─── Top-level entry point ────────────────────────────────────────────────

export function generateVaptReportHtml(model: VaptReportModel): string {
  const meta = PROVIDER_META[model.provider];
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VAPT Report — ${esc(model.targetName)}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:#0f172a;background:#f1f5f9;line-height:1.5}
  .page{max-width:960px;margin:0 auto;background:#fff}

  /* ── Cover ── */
  .cover{padding:56px 48px 40px;border-bottom:4px solid ${meta.color};text-align:center}
  .cover-badge{display:inline-block;color:#fff;font-size:12px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;padding:4px 14px;border-radius:999px;margin-bottom:20px}
  .cover h1{font-size:28px;font-weight:800;color:#0f172a;margin-bottom:8px}
  .cover-target{font-size:20px;font-weight:600;color:${meta.color};margin-bottom:4px}
  .cover-id{font-size:13px;color:#64748b;margin-bottom:24px}
  .cover-meta{display:flex;justify-content:center;gap:48px;margin-bottom:24px;flex-wrap:wrap}
  .cover-meta-label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#94a3b8;margin-bottom:2px}
  .cover-meta-val{display:block;font-size:14px;font-weight:600;color:#0f172a}
  .cover-confidential{font-size:11px;color:#94a3b8;font-style:italic;max-width:520px;margin:0 auto}
  .cover-filters{display:inline-flex;flex-direction:column;gap:3px;background:#fffbeb;border:1px solid #fde68a;border-radius:6px;padding:8px 16px;margin-bottom:20px;max-width:640px}
  .cover-filters-label{font-size:10px;font-weight:800;letter-spacing:.04em;color:#92400e}
  .cover-filters-val{font-size:11.5px;color:#78350f}
  .mono{font-family:'SF Mono',Consolas,monospace}

  /* ── Sections ── */
  .section{padding:32px 48px;border-bottom:1px solid #e2e8f0}
  .section:last-child{border-bottom:none}
  h2{font-size:17px;font-weight:800;color:#0f172a;margin-bottom:16px;padding-bottom:8px;border-bottom:2px solid #e2e8f0}
  .muted{color:#94a3b8;font-size:13px}
  .exec-narrative{margin-top:16px;font-size:13.5px;color:#334155;line-height:1.7}

  /* ── Stat grid ── */
  .stat-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}
  .stat{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px 8px;text-align:center}
  .stat-val{font-size:26px;font-weight:800;color:#0f172a}
  .stat-val.critical{color:${SEV_COLOR.CRITICAL}} .stat-val.high{color:${SEV_COLOR.HIGH}}
  .stat-val.medium{color:${SEV_COLOR.MEDIUM}} .stat-val.low{color:${SEV_COLOR.LOW}} .stat-val.info{color:${SEV_COLOR.INFO}}
  .stat-lbl{font-size:10.5px;color:#64748b;margin-top:4px;text-transform:uppercase;letter-spacing:.03em}

  /* ── Gauges ── */
  .gauge-grid{display:flex;flex-wrap:wrap;gap:28px;margin-bottom:20px}
  .gauge{display:flex;flex-direction:column;align-items:center;gap:2px;width:96px}
  .gauge-label{font-size:11px;font-weight:700;color:#334155;text-align:center;line-height:1.2}
  .gauge-sublabel{font-size:9.5px;color:#94a3b8}

  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th{background:#f1f5f9;text-align:left;padding:8px 10px;font-weight:700;color:#475569;border-bottom:2px solid #e2e8f0}
  td{padding:7px 10px;border-bottom:1px solid #f1f5f9;vertical-align:top}
  td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}

  /* ── IAM Users ── */
  .iam-row-flagged{background:#fef2f2}
  .iam-user-cell{font-weight:700;color:#0f172a;white-space:nowrap}
  .iam-detail-cell{font-size:11px;color:#475569;line-height:1.8}
  .open-ended-badge{display:inline-block;font-size:10px;font-weight:800;color:${SEV_COLOR.CRITICAL};background:#fee2e2;padding:2px 8px;border-radius:999px}
  .ok-val{color:#16a34a;font-weight:600}
  .stale-val{color:${SEV_COLOR.CRITICAL};font-weight:600}
  .muted{color:#94a3b8}
  .policy-chip{display:inline-block;font-size:10.5px;padding:1px 7px;border-radius:4px;background:#f1f5f9;color:#475569;margin:1px 3px 1px 0}
  .policy-chip-admin{background:#fee2e2;color:${SEV_COLOR.CRITICAL};font-weight:700}

  /* ── Findings ── */
  .severity-group{margin-bottom:20px}
  .severity-group h3{font-size:13px;font-weight:800;text-transform:uppercase;letter-spacing:.03em;margin-bottom:10px}
  .severity-group h3 .count{color:#94a3b8;font-weight:600}
  .finding-card{border:1px solid #e2e8f0;border-left:4px solid #94a3b8;border-radius:6px;padding:12px 14px;margin-bottom:10px;break-inside:avoid;page-break-inside:avoid}
  .finding-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px}
  .sev-badge{color:#fff;font-size:10px;font-weight:800;padding:2px 8px;border-radius:4px;letter-spacing:.03em}
  .finding-title{font-size:13.5px;font-weight:700;color:#0f172a;flex:1}
  .finding-service{font-size:10px;font-weight:700;color:#64748b;background:#f1f5f9;padding:2px 8px;border-radius:4px}
  .compliance-chip{font-size:10px;font-weight:600;color:#4338ca;background:#eef2ff;padding:2px 8px;border-radius:4px;border:1px solid #c7d2fe}
  .finding-resource{font-size:11.5px;color:#64748b;margin-bottom:6px}
  .finding-body{display:grid;grid-template-columns:1fr 1fr;gap:16px;font-size:12px;color:#334155}
  .finding-body h4{font-size:10px;text-transform:uppercase;letter-spacing:.03em;color:#94a3b8;margin-bottom:3px}
  .finding-foot{font-size:10.5px;color:#94a3b8;margin-top:8px;text-align:right}

  .footer{padding:20px 48px;text-align:center;font-size:11px;color:#94a3b8}

  @page{size:A4;margin:14mm 12mm}
  @media print{
    body{background:#fff}
    .page{max-width:none}
    .section{break-inside:auto}
    .cover{break-after:page;page-break-after:always}
  }
</style>
</head>
<body>
<div class="page">
${coverSection(model)}
${execSummarySection(model)}
${frameworkSection(model.frameworkScores)}
${iamUsersSection(model)}
${findingsSection(model)}
<div class="footer">
  Generated by Cloud Scanner &middot; ${fmtDateTime(model.generatedAt)}<br>
  This report is confidential and intended solely for authorized recipients.
</div>
</div>
</body>
</html>`;
}
