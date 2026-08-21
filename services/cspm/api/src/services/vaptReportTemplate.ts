/**
 * Renders a VaptReportModel (see vaptReportService.ts) into a single,
 * self-contained, print-ready HTML document — cover section, executive
 * summary, the Framework Score Overview (server-rendered SVG gauges,
 * matching the web app's Compliance/Reports tab visual language 1:1),
 * and the full findings list grouped by severity with remediation guidance.
 *
 * Layout and typography are tuned with Inter & JetBrains Mono fonts,
 * clean severity KPI cards, advisory finding cards, and @page print rules
 * so every finding renders identically when viewed in-browser or printed to PDF.
 */

import type { VaptReportModel, VaptFinding, VaptFrameworkScoreSummary, VaptIamUser } from './vaptReportService';

// ─── Shared palette (kept in sync with frontend severity/score colors) ──

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#dc2626',
  HIGH:     '#ea580c',
  MEDIUM:   '#d97706',
  LOW:      '#2563eb',
  INFO:     '#64748b',
};

const PROVIDER_META: Record<VaptReportModel['provider'], { label: string; bg: string; color: string; border: string }> = {
  AWS:   { label: 'Amazon Web Services', bg: '#fff7ed', color: '#c2410c', border: '#ffedd5' },
  AZURE: { label: 'Microsoft Azure',     bg: '#eff6ff', color: '#1d4ed8', border: '#dbeafe' },
  GCP:   { label: 'Google Cloud Platform', bg: '#f0fdf4', color: '#15803d', border: '#dcfce7' },
};

const RATING_STYLE: Record<VaptReportModel['riskRating'], { bg: string; color: string; border: string }> = {
  CRITICAL: { bg: '#fef2f2', color: '#dc2626', border: '#fecaca' },
  HIGH:     { bg: '#fff7ed', color: '#ea580c', border: '#ffedd5' },
  MODERATE: { bg: '#fffbebf', color: '#d97706', border: '#fef3c7' },
  LOW:      { bg: '#f0fdf4', color: '#16a34a', border: '#dcfce7' },
};

function gaugeColor(score: number): string {
  if (score >= 80) return '#10b981';
  if (score >= 60) return '#f59e0b';
  return '#ef4444';
}

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

function svgGauge(score: number, label: string, sublabel: string): string {
  const size = 88, r = 34, circ = 2 * Math.PI * r, offset = circ * (1 - score / 100);
  const color = gaugeColor(score);
  return `
    <div class="gauge">
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
        <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="#f1f5f9" stroke-width="7"/>
        <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${color}" stroke-width="7"
          stroke-dasharray="${circ}" stroke-dashoffset="${offset}" stroke-linecap="round"
          transform="rotate(-90 ${size / 2} ${size / 2})"/>
        <text x="${size / 2}" y="${size / 2 + 5}" text-anchor="middle" font-size="15" font-weight="800" fill="${color}">${score}%</text>
      </svg>
      <p class="gauge-label">${esc(label)}</p>
      <p class="gauge-sublabel">${esc(sublabel)}</p>
    </div>`;
}

function filtersBanner(model: VaptReportModel): string {
  const f = model.appliedFilters;
  const parts: string[] = [];
  if (f.tags.length)          parts.push(`Tags: ${f.tags.map(esc).join(', ')}`);
  if (f.region.length)        parts.push(`Region: ${f.region.map(esc).join(', ')}`);
  if (f.resourceGroup.length) parts.push(`Resource Group: ${f.resourceGroup.map(esc).join(', ')}`);
  if (parts.length === 0) return '';
  return `
  <div class="cover-filters">
    <span class="cover-filters-label">FILTERED REPORT — DOES NOT COVER FULL TARGET</span>
    <span class="cover-filters-val">${parts.join(' &nbsp;&middot;&nbsp; ')}</span>
  </div>`;
}

const PROVIDER_LOGOS: Record<VaptReportModel['provider'], string> = {
  AWS: `<svg height="44" viewBox="-.1 1.1 304.9 179.8" xmlns="http://www.w3.org/2000/svg"><path d="m86.4 66.4c0 3.7.4 6.7 1.1 8.9.8 2.2 1.8 4.6 3.2 7.2.5.8.7 1.6.7 2.3 0 1-.6 2-1.9 3l-6.3 4.2c-.9.6-1.8.9-2.6.9-1 0-2-.5-3-1.4-1.4-1.5-2.6-3.1-3.6-4.7-1-1.7-2-3.6-3.1-5.9-7.8 9.2-17.6 13.8-29.4 13.8-8.4 0-15.1-2.4-20-7.2s-7.4-11.2-7.4-19.2c0-8.5 3-15.4 9.1-20.6s14.2-7.8 24.5-7.8c3.4 0 6.9.3 10.6.8s7.5 1.3 11.5 2.2v-7.3c0-7.6-1.6-12.9-4.7-16-3.2-3.1-8.6-4.6-16.3-4.6-3.5 0-7.1.4-10.8 1.3s-7.3 2-10.8 3.4c-1.6.7-2.8 1.1-3.5 1.3s-1.2.3-1.6.3c-1.4 0-2.1-1-2.1-3.1v-4.9c0-1.6.2-2.8.7-3.5s1.4-1.4 2.8-2.1c3.5-1.8 7.7-3.3 12.6-4.5 4.9-1.3 10.1-1.9 15.6-1.9 11.9 0 20.6 2.7 26.2 8.1 5.5 5.4 8.3 13.6 8.3 24.6v32.4zm-40.6 15.2c3.3 0 6.7-.6 10.3-1.8s6.8-3.4 9.5-6.4c1.6-1.9 2.8-4 3.4-6.4s1-5.3 1-8.7v-4.2c-2.9-.7-6-1.3-9.2-1.7s-6.3-.6-9.4-.6c-6.7 0-11.6 1.3-14.9 4s-4.9 6.5-4.9 11.5c0 4.7 1.2 8.2 3.7 10.6 2.4 2.5 5.9 3.7 10.5 3.7zm80.3 10.8c-1.8 0-3-.3-3.8-1-.8-.6-1.5-2-2.1-3.9l-23.5-77.3c-.6-2-.9-3.3-.9-4 0-1.6.8-2.5 2.4-2.5h9.8c1.9 0 3.2.3 3.9 1 .8.6 1.4 2 2 3.9l16.8 66.2 15.6-66.2c.5-2 1.1-3.3 1.9-3.9s2.2-1 4-1h8c1.9 0 3.2.3 4 1 .8.6 1.5 2 1.9 3.9l15.8 67 17.3-67c.6-2 1.3-3.3 2-3.9.8-.6 2.1-1 3.9-1h9.3c1.6 0 2.5.8 2.5 2.5 0 .5-.1 1-.2 1.6s-.3 1.4-.7 2.5l-24.1 77.3c-.6 2-1.3 3.3-2.1 3.9s-2.1 1-3.8 1h-8.6c-1.9 0-3.2-.3-4-1s-1.5-2-1.9-4l-15.5-64.5-15.4 64.4c-.5 2-1.1 3.3-1.9 4s-2.2 1-4 1zm128.5 2.7c-5.2 0-10.4-.6-15.4-1.8s-8.9-2.5-11.5-4c-1.6-.9-2.7-1.9-3.1-2.8s-.6-1.9-.6-2.8v-5.1c0-2.1.8-3.1 2.3-3.1.6 0 1.2.1 1.8.3s1.5.6 2.5 1c3.4 1.5 7.1 2.7 11 3.5 4 .8 7.9 1.2 11.9 1.2 6.3 0 11.2-1.1 14.6-3.3s5.2-5.4 5.2-9.5c0-2.8-.9-5.1-2.7-7s-5.2-3.6-10.1-5.2l-14.5-4.5c-7.3-2.3-12.7-5.7-16-10.2-3.3-4.4-5-9.3-5-14.5 0-4.2.9-7.9 2.7-11.1s4.2-6 7.2-8.2c3-2.3 6.4-4 10.4-5.2s8.2-1.7 12.6-1.7c2.2 0 4.5.1 6.7.4 2.3.3 4.4.7 6.5 1.1 2 .5 3.9 1 5.7 1.6s3.2 1.2 4.2 1.8c1.4.8 2.4 1.6 3 2.5.6.8.9 1.9.9 3.3v4.7c0 2.1-.8 3.2-2.3 3.2-.8 0-2.1-.4-3.8-1.2-5.7-2.6-12.1-3.9-19.2-3.9-5.7 0-10.2.9-13.3 2.8s-4.7 4.8-4.7 8.9c0 2.8 1 5.2 3 7.1s5.7 3.8 11 5.5l14.2 4.5c7.2 2.3 12.4 5.5 15.5 9.6s4.6 8.8 4.6 14c0 4.3-.9 8.2-2.6 11.6-1.8 3.4-4.2 6.4-7.3 8.8-3.1 2.5-6.8 4.3-11.1 5.6-4.5 1.4-9.2 2.1-14.3 2.1z" fill="#252f3e"/><g clip-rule="evenodd" fill="#f90" fill-rule="evenodd"><path d="m273.5 143.7c-32.9 24.3-80.7 37.2-121.8 37.2-57.6 0-109.5-21.3-148.7-56.7-3.1-2.8-.3-6.6 3.4-4.4 42.4 24.6 94.7 39.5 148.8 39.5 36.5 0 76.6-7.6 113.5-23.2 5.5-2.5 10.2 3.6 4.8 7.6z"/><path d="m287.2 128.1c-4.2-5.4-27.8-2.6-38.5-1.3-3.2.4-3.7-2.4-.8-4.5 18.8-13.2 49.7-9.4 53.3-5 3.6 4.5-1 35.4-18.6 50.2-2.7 2.3-5.3 1.1-4.1-1.9 4-9.9 12.9-32.2 8.7-37.5z"/></g></svg>`,
  AZURE: `<svg height="40" xmlns="http://www.w3.org/2000/svg" viewBox="-0.45 0.38 800.88 754.22"><linearGradient id="a" gradientUnits="userSpaceOnUse" x1="353.1" x2="107.1" y1="56.3" y2="783"><stop offset="0" stop-color="#114a8b"/><stop offset="1" stop-color="#0669bc"/></linearGradient><linearGradient id="b" gradientUnits="userSpaceOnUse" x1="429.8" x2="372.9" y1="394.9" y2="414.2"><stop offset="0" stop-opacity=".3"/><stop offset=".1" stop-opacity=".2"/><stop offset=".3" stop-opacity=".1"/><stop offset=".6" stop-opacity=".1"/><stop offset="1" stop-opacity="0"/></linearGradient><linearGradient id="c" gradientUnits="userSpaceOnUse" x1="398.4" x2="668.4" y1="35.1" y2="754.4"><stop offset="0" stop-color="#3ccbf4"/><stop offset="1" stop-color="#2892df"/></linearGradient><path d="M266.71.4h236.71L257.69 728.9a37.8 37.8 0 0 1-5.42 10.38c-2.33 3.16-5.14 5.93-8.33 8.22s-6.71 4.07-10.45 5.27-7.64 1.82-11.56 1.82H37.71c-5.98 0-11.88-1.42-17.2-4.16A37.636 37.636 0 0 1 7.1 738.87a37.762 37.762 0 0 1-6.66-16.41c-.89-5.92-.35-11.97 1.56-17.64L230.94 26.07c1.25-3.72 3.08-7.22 5.42-10.38 2.33-3.16 5.15-5.93 8.33-8.22 3.19-2.29 6.71-4.07 10.45-5.27S262.78.38 266.7.38v.01z" fill="url(#a)"/><path d="M703.07 754.59H490.52c-2.37 0-4.74-.22-7.08-.67-2.33-.44-4.62-1.1-6.83-1.97s-4.33-1.95-6.34-3.21a38.188 38.188 0 0 1-5.63-4.34l-241.2-225.26a17.423 17.423 0 0 1-5.1-8.88 17.383 17.383 0 0 1 7.17-18.21c2.89-1.96 6.3-3.01 9.79-3.01h375.36l92.39 265.56z" fill="#0078d4"/><path d="M504.27.4l-165.7 488.69 270.74-.06 92.87 265.56H490.43c-2.19-.02-4.38-.22-6.54-.61s-4.28-.96-6.34-1.72a38.484 38.484 0 0 1-11.36-6.51L303.37 593.79l-45.58 134.42c-1.18 3.36-2.8 6.55-4.82 9.48a40.479 40.479 0 0 1-16.05 13.67 40.03 40.03 0 0 1-10.13 3.23H37.82c-6.04.02-12-1.42-17.37-4.2A37.664 37.664 0 0 1 .43 722a37.77 37.77 0 0 1 1.87-17.79L230.87 26.58c1.19-3.79 2.98-7.36 5.3-10.58 2.31-3.22 5.13-6.06 8.33-8.4s6.76-4.16 10.53-5.38S262.75.38 266.72.4h237.56z" fill="url(#b)"/><path d="M797.99 704.82a37.847 37.847 0 0 1 1.57 17.64 37.867 37.867 0 0 1-6.65 16.41 37.691 37.691 0 0 1-30.61 15.72H498.48c5.98 0 11.88-1.43 17.21-4.16 5.32-2.73 9.92-6.7 13.41-11.56s5.77-10.49 6.66-16.41.35-11.97-1.56-17.64L305.25 26.05a37.713 37.713 0 0 0-13.73-18.58c-3.18-2.29-6.7-4.06-10.43-5.26S273.46.4 269.55.4h263.81c3.92 0 7.81.61 11.55 1.81 3.73 1.2 7.25 2.98 10.44 5.26 3.18 2.29 5.99 5.06 8.32 8.21s4.15 6.65 5.41 10.37l228.95 678.77z" fill="url(#c)"/></svg>`,
  GCP: `<svg height="40" viewBox="0 0 467 467" xmlns="http://www.w3.org/2000/svg"><path d="M467 238.5c0-16-1.5-31.5-4.2-46.5H238.5v88.2h128.5c-5.5 29.8-22.3 55-47.5 71.8v59.7h76.8C441.2 369.8 467 309.2 467 238.5z" fill="#4285F4"/><path d="M238.5 467c61.7 0 113.5-20.5 151.3-55.3l-76.8-59.7c-20.5 13.7-46.7 21.8-74.5 21.8-57.3 0-105.8-38.7-123.1-90.8H36.3v61.7C74.3 420 150.8 467 238.5 467z" fill="#34A853"/><path d="M115.4 283c-4.4-13.2-6.9-27.3-6.9-44.5s2.5-31.3 6.9-44.5v-61.7H36.3C13.2 178.5 0 207 0 238.5s13.2 60 36.3 106.2l79.1-61.7z" fill="#FBBC05"/><path d="M238.5 91.3c33.5 0 63.5 11.5 87.2 34.2l65.4-65.4C351.8 22.3 300 0 238.5 0 150.8 0 74.3 47 36.3 122.3l79.1 61.7c17.3-52.1 65.8-92.7 123.1-92.7z" fill="#EA4335"/></svg>`,
};

function coverSection(model: VaptReportModel): string {
  const meta = PROVIDER_META[model.provider];
  const svgLogo = PROVIDER_LOGOS[model.provider];
  const rStyle = RATING_STYLE[model.riskRating];
  return `
<div class="cover">
  <div class="cover-logo-wrap">
    ${svgLogo}
  </div>
  <h1 class="cover-title">VAPT Security Assessment Report</h1>
  <p class="cover-target">${esc(model.targetName)}</p>
  <p class="cover-id">${esc(model.provider)} ID: <span class="mono">${esc(model.targetExternalId)}</span></p>

  <div class="cover-meta-grid">
    <div class="meta-card">
      <span class="meta-label">Generated</span>
      <span class="meta-val">${fmtDateTime(model.generatedAt)}</span>
    </div>
    <div class="meta-card">
      <span class="meta-label">Last Scan</span>
      <span class="meta-val">${model.lastScanAt ? fmtDateTime(model.lastScanAt) : 'No completed scan yet'}</span>
    </div>
    <div class="meta-card highlight">
      <span class="meta-label">Overall Risk Rating</span>
      <span class="risk-badge" style="color:${rStyle.color};">
        ${model.riskRating}
      </span>
    </div>
  </div>

  ${filtersBanner(model)}

  <p class="cover-confidential">
    CONFIDENTIAL &mdash; Prepared for authorized recipients only. Distribution outside the intended audience is prohibited.
  </p>
</div>`;
}

function execSummarySection(model: VaptReportModel): string {
  const s = model.summary;
  const rStyle = RATING_STYLE[model.riskRating];
  return `
<div class="section">
  <h2 class="section-title">Executive Summary</h2>
  <div class="stat-grid">
    <div class="stat-card critical">
      <div class="stat-val text-critical">${s.critical}</div>
      <div class="stat-lbl">Critical</div>
    </div>
    <div class="stat-card high">
      <div class="stat-val text-high">${s.high}</div>
      <div class="stat-lbl">High</div>
    </div>
    <div class="stat-card medium">
      <div class="stat-val text-medium">${s.medium}</div>
      <div class="stat-lbl">Medium</div>
    </div>
    <div class="stat-card low">
      <div class="stat-val text-low">${s.low}</div>
      <div class="stat-lbl">Low</div>
    </div>
    <div class="stat-card info">
      <div class="stat-val text-info">${s.info}</div>
      <div class="stat-lbl">Info</div>
    </div>
    <div class="stat-card total">
      <div class="stat-val text-total">${s.total}</div>
      <div class="stat-lbl">Total Open Findings</div>
    </div>
  </div>

  <p class="exec-narrative">
    This security assessment identified <strong class="text-dark">${s.total}</strong> open finding${s.total === 1 ? '' : 's'} across
    <strong class="text-dark">${esc(model.targetName)}</strong> (${esc(model.provider)}), yielding a composite risk score of
    <strong class="text-dark">${model.riskScore}</strong> — rated <span class="inline-risk" style="background:${rStyle.bg};color:${rStyle.color};border:1px solid ${rStyle.border}">${model.riskRating}</span>.
    ${s.critical > 0 ? `<strong class="text-critical">${s.critical} critical-severity finding${s.critical === 1 ? '' : 's'}</strong> require immediate remediation. ` : ''}
    ${s.high > 0 ? `<strong>${s.high} high-severity finding${s.high === 1 ? '' : 's'}</strong> should be prioritized in the current remediation cycle.` : ''}
  </p>
</div>`;
}

function frameworkSection(scores: VaptFrameworkScoreSummary[] | null): string {
  if (!scores || scores.length === 0) {
    return `
<div class="section">
  <h2 class="section-title">Compliance Framework Score Overview</h2>
  <p class="muted">Compliance framework scoring is not yet available for this cloud provider.</p>
</div>`;
  }
  const gauges = scores.map(f => svgGauge(f.score, f.shortName, `${f.passingControls}/${f.totalControls} passed`)).join('');
  const rows = scores.map(f => `
    <tr>
      <td class="font-bold">${esc(f.frameworkName)}</td>
      <td class="num font-semibold text-emerald">${f.passingControls}</td>
      <td class="num font-semibold text-critical">${f.failingControls}</td>
      <td class="num text-muted">${f.notEvaluatedControls}</td>
      <td class="num font-bold" style="color:${gaugeColor(f.score)}">${f.score}%</td>
    </tr>`).join('');
  return `
<div class="section">
  <h2 class="section-title">Compliance Framework Score Overview</h2>
  <div class="gauge-grid">${gauges}</div>
  <div class="table-container">
    <table>
      <thead>
        <tr>
          <th>Framework</th>
          <th class="num">Passing</th>
          <th class="num">Failing</th>
          <th class="num">Not Evaluated</th>
          <th class="num">Score</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  </div>
</div>`;
}

function policyChip(label: string, isAdmin: boolean): string {
  return `<span class="policy-chip${isAdmin ? ' policy-chip-admin' : ''}">${esc(label)}${isAdmin ? ' <span class="admin-tag">(full admin)</span>' : ''}</span>`;
}

function iamUserRow(u: VaptIamUser): string {
  const policies = [
    ...u.directPolicies.map(p => policyChip(p.name, p.isAdminEquivalent)),
    ...u.groupPolicies.map(p => policyChip(`${p.policyName} (via ${p.groupName})`, p.isAdminEquivalent)),
  ].join('') || '<span class="muted">none</span>';
  const roles = u.assumableRoles
    .map(r => policyChip(`${r.roleName}${r.assumableBy === 'wildcard' ? ' (wildcard)' : ''}`, r.isAdminEquivalent))
    .join('') || '<span class="muted">none</span>';
  const groups = u.groups.length > 0 ? u.groups.map(g => `<span class="policy-chip">${esc(g)}</span>`).join('') : '<span class="muted">none</span>';

  const passwordCell = !u.passwordEnabled
    ? '<span class="muted">no console access</span>'
    : `<span${u.passwordStale ? ' class="stale-val"' : ' class="text-dark"'}>${u.passwordAgeDays ?? '—'}d ago</span>`;
  const keyCell = u.accessKeysActive === 0
    ? '<span class="muted">no active keys</span>'
    : u.hasNeverUsedActiveKey
      ? '<span class="stale-val">never used</span>'
      : `<span${u.keyStale ? ' class="stale-val"' : ' class="text-dark"'}>${u.accessKeyAgeDays ?? '—'}d ago</span>`;

  return `
<tr class="${u.hasOpenEndedAccess ? 'iam-row-flagged' : ''}">
  <td class="iam-user-cell">${esc(u.userName)}</td>
  <td>${u.hasOpenEndedAccess ? '<span class="open-ended-badge">Open-ended (admin)</span>' : '<span class="scoped-badge">Scoped</span>'}</td>
  <td>${u.mfaEnabled ? '<span class="ok-val">Enabled</span>' : '<span class="stale-val">Not enabled</span>'}</td>
  <td>${passwordCell}</td>
  <td>${keyCell}</td>
  <td class="iam-detail-cell">
    <div class="detail-group"><div class="detail-label">Groups</div><div class="detail-chips">${groups}</div></div>
    <div class="detail-group"><div class="detail-label">Policies</div><div class="detail-chips">${policies}</div></div>
    <div class="detail-group" style="margin-bottom:0"><div class="detail-label">Assumable roles</div><div class="detail-chips">${roles}</div></div>
  </td>
</tr>`;
}

function iamUsersSection(model: VaptReportModel): string {
  if (model.iamUsers === null) return '';
  if (model.iamUsers.length === 0) {
    return `
<div class="section">
  <h2 class="section-title">IAM Users</h2>
  <p class="muted">No IAM users found for this account.</p>
</div>`;
  }
  const openEndedCount = model.iamUsers.filter(u => u.hasOpenEndedAccess).length;
  const hygieneCount = model.iamUsers.filter(u => !u.mfaEnabled || u.passwordStale || u.keyStale).length;
  const rows = model.iamUsers.map(iamUserRow).join('');
  return `
<div class="section">
  <h2 class="section-title">IAM Users</h2>
  <p class="exec-narrative" style="margin-top:0;margin-bottom:16px">
    Effective permissions, assumable roles, and access hygiene per user.
    ${openEndedCount > 0 ? `<strong style="color:${SEV_COLOR.HIGH}">${openEndedCount} user${openEndedCount === 1 ? '' : 's'} with open-ended (admin-equivalent) access.</strong> ` : ''}
    ${hygieneCount > 0 ? `<strong style="color:${SEV_COLOR.MEDIUM}">${hygieneCount} user${hygieneCount === 1 ? '' : 's'} with an MFA, password, or access-key hygiene issue.</strong>` : ''}
  </p>
  <div class="table-container">
    <table>
      <thead><tr><th>User</th><th>Access Level</th><th>MFA</th><th>Password Changed</th><th>Access Key Last Used</th><th>Groups / Policies / Roles</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>
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
    <div class="finding-box">
      <h4>Description</h4>
      <p>${esc(f.description)}</p>
    </div>
    <div class="finding-box">
      <h4>Remediation Guidance</h4>
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
  <h2 class="section-title">Detailed Findings</h2>
  <p class="muted">No open findings — this target is currently clean.</p>
</div>`;
  }

  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const groups = order
    .map(sev => ({ sev, items: model.findings.filter(f => f.severity === sev) }))
    .filter(g => g.items.length > 0);

  const groupsHtml = groups.map(g => `
    <div class="severity-group">
      <h3 class="sev-group-title" style="color:${SEV_COLOR[g.sev]}">${g.sev} <span class="count">(${g.items.length})</span></h3>
      ${g.items.map(findingCard).join('')}
    </div>`).join('');

  const truncNote = model.findingsTruncated
    ? `<p class="muted mb-3">Showing ${model.findings.length} of ${model.findingsTotalCount} open findings. Export the full list from Operations &rarr; Reports for the complete set.</p>`
    : '';

  return `
<div class="section">
  <h2 class="section-title">Detailed Findings</h2>
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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#0f172a;background:#f8fafc;line-height:1.5;-webkit-font-smoothing:antialiased}
  .page{max-width:960px;margin:0 auto;background:#fff;box-shadow:0 10px 30px rgba(0,0,0,0.06)}

  /* ── Cover ── */
  .cover{padding:56px 52px 44px;border-bottom:4px solid ${meta.color};text-align:center;background:#fff}
  .cover-logo-wrap{display:flex;justify-content:center;align-items:center;margin-bottom:32px}
  .cover-logo-wrap svg{height:56px !important;width:auto !important}
  .cover-title{font-size:34px;font-weight:800;color:#0f172a;letter-spacing:-0.03em;margin-bottom:16px}
  .cover-target{font-size:24px;font-weight:600;color:${meta.color};letter-spacing:-0.02em;margin-bottom:8px}
  .cover-id{font-size:14px;color:#64748b;margin-bottom:56px}
  
  .cover-meta-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;max-width:800px;margin:0 auto 48px;text-align:center}
  .meta-card{padding:8px}
  .meta-label{display:block;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;margin-bottom:8px}
  .meta-val{display:block;font-size:15px;font-weight:700;color:#0f172a}
  .risk-badge{display:inline-block;font-size:15px;font-weight:800;letter-spacing:.02em;}

  .cover-confidential{font-size:11.5px;color:#94a3b8;font-weight:500;white-space:nowrap;margin:0 auto;line-height:1.6;font-style:italic}
  .cover-filters{display:inline-flex;flex-direction:column;gap:3px;background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:10px 18px;margin-bottom:24px;max-width:640px;text-align:left}
  .cover-filters-label{font-size:10px;font-weight:800;letter-spacing:.06em;color:#92400e}
  .cover-filters-val{font-size:12px;color:#78350f;font-weight:500}
  .mono{font-family:'JetBrains Mono','SF Mono',Consolas,monospace;font-weight:600}

  /* ── Sections ── */
  .section{padding:36px 52px;border-bottom:1px solid #e2e8f0}
  .section:last-child{border-bottom:none}
  .section-title{font-size:18px;font-weight:800;color:#0f172a;letter-spacing:-0.02em;margin-bottom:20px;padding-bottom:10px;border-bottom:2px solid #f1f5f9}
  .muted{color:#94a3b8;font-size:13px;font-weight:500}
  .mb-3{margin-bottom:12px}
  .text-dark{color:#0f172a}
  .exec-narrative{margin-top:20px;font-size:14px;color:#334155;line-height:1.75;font-weight:400}
  .inline-risk{display:inline-block;font-size:11px;font-weight:800;padding:1px 7px;border-radius:4px;letter-spacing:.03em}

  /* ── Stat grid ── */
  .stat-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}
  .stat-card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:16px 10px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,0.02)}
  .stat-card.critical{border-top:4px solid ${SEV_COLOR.CRITICAL}}
  .stat-card.high{border-top:4px solid ${SEV_COLOR.HIGH}}
  .stat-card.medium{border-top:4px solid ${SEV_COLOR.MEDIUM}}
  .stat-card.low{border-top:4px solid ${SEV_COLOR.LOW}}
  .stat-card.info{border-top:4px solid ${SEV_COLOR.INFO}}
  .stat-card.total{border-top:4px solid #0f172a;background:#f8fafc}
  
  .stat-val{font-size:28px;font-weight:800;line-height:1.1;letter-spacing:-0.03em}
  .text-critical{color:${SEV_COLOR.CRITICAL}} .text-high{color:${SEV_COLOR.HIGH}}
  .text-medium{color:${SEV_COLOR.MEDIUM}} .text-low{color:${SEV_COLOR.LOW}} .text-info{color:${SEV_COLOR.INFO}} .text-total{color:#0f172a}
  .stat-lbl{font-size:10.5px;color:#64748b;margin-top:6px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}

  /* ── Gauges & Tables ── */
  .gauge-grid{display:flex;flex-wrap:nowrap;justify-content:space-between;gap:12px;margin-bottom:24px;overflow:hidden}
  .gauge{display:flex;flex-direction:column;align-items:center;gap:3px;flex:1;max-width:96px}
  .gauge-label{font-size:11.5px;font-weight:700;color:#0f172a;text-align:center;line-height:1.2}
  .gauge-sublabel{font-size:10px;color:#94a3b8;font-weight:500}

  .table-container{border:1px solid #e2e8f0;border-radius:10px;overflow:hidden}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th{background:#f8fafc;text-align:left;padding:12px 16px;font-weight:700;color:#475569;border-bottom:1px solid #e2e8f0;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
  td{padding:16px;border-bottom:1px solid #f1f5f9;vertical-align:top;color:#334155}
  tr:last-child td{border-bottom:none}
  td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
  .font-bold{font-weight:700}
  .font-semibold{font-weight:600}
  .text-emerald{color:#10b981}

  /* ── IAM Users ── */
  .iam-row-flagged td:first-child{box-shadow:inset 4px 0 0 ${SEV_COLOR.CRITICAL}}
  .iam-user-cell{font-weight:700;color:#0f172a;white-space:nowrap}
  .iam-detail-cell{font-size:11.5px;color:#475569;line-height:1.6}
  .detail-group{margin-bottom:12px}
  .detail-label{font-size:9.5px;font-weight:800;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8;margin-bottom:4px}
  .detail-chips{display:flex;flex-wrap:wrap;gap:4px}
  .open-ended-badge{display:inline-block;font-size:10px;font-weight:800;color:#fff;background:${SEV_COLOR.CRITICAL};padding:3px 8px;border-radius:6px;letter-spacing:.02em}
  .scoped-badge{display:inline-block;font-size:10px;font-weight:700;color:#475569;background:#f1f5f9;border:1px solid #e2e8f0;padding:2px 8px;border-radius:6px}
  .ok-val{color:#16a34a;font-weight:700}
  .stale-val{color:${SEV_COLOR.CRITICAL};font-weight:700}
  .policy-chip{display:inline-flex;align-items:center;gap:3px;font-size:10.5px;font-weight:600;padding:3px 8px;border-radius:6px;background:#f8fafc;color:#334155;border:1px solid #e2e8f0}
  .policy-chip-admin{background:#fff1f2;color:#be123c;border-color:#fecdd3;font-weight:700}
  .admin-tag{font-size:9px;text-transform:uppercase;font-weight:800;color:#e11d48;margin-left:2px}

  /* ── Findings ── */
  .severity-group{margin-bottom:24px}
  .sev-group-title{font-size:13px;font-weight:800;text-transform:uppercase;letter-spacing:.05em;margin-bottom:12px}
  .sev-group-title .count{color:#94a3b8;font-weight:600}
  .finding-card{background:#fff;border:1px solid #e2e8f0;border-left:5px solid #94a3b8;border-radius:10px;padding:16px 18px;margin-bottom:12px;box-shadow:0 1px 3px rgba(0,0,0,0.02);break-inside:avoid;page-break-inside:avoid}
  .finding-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px}
  .sev-badge{color:#fff;font-size:10px;font-weight:800;padding:3px 8px;border-radius:5px;letter-spacing:.04em}
  .finding-title{font-size:14px;font-weight:700;color:#0f172a;flex:1;letter-spacing:-0.01em}
  .finding-service{font-size:10px;font-weight:700;color:#475569;background:#f1f5f9;border:1px solid #e2e8f0;padding:2px 8px;border-radius:5px}
  .compliance-chip{font-size:10px;font-weight:700;color:#4338ca;background:#eef2ff;padding:2px 8px;border-radius:5px;border:1px solid #c7d2fe}
  .finding-resource{font-size:12px;color:#64748b;margin-bottom:10px;font-weight:500}
  .finding-body{display:grid;grid-template-columns:1fr 1fr;gap:14px;font-size:12px;color:#334155}
  .finding-box{background:#f8fafc;border:1px solid #f1f5f9;border-radius:8px;padding:10px 12px}
  .finding-box h4{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:#64748b;font-weight:800;margin-bottom:4px}
  .finding-foot{font-size:11px;color:#94a3b8;font-weight:500;margin-top:10px;text-align:right}

  .footer{padding:24px 52px;text-align:center;font-size:11.5px;color:#94a3b8;font-weight:500;line-height:1.6}

  @page{size:A4;margin:12mm 10mm}
  @media print{
    body{background:#fff}
    .page{max-width:none;box-shadow:none}
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
