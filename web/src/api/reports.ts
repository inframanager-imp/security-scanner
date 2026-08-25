import { useAuthStore } from '../store/authStore';
import { refreshAccessToken, ApiRequestError, api } from './client';

const BASE_URL = '/api/cspm';

export type ReportProvider = 'AWS' | 'AZURE' | 'GCP';

export interface VaptReportFilters {
  tags?:          string[]; // all providers — OR-match (finding has ANY of these tags)
  region?:        string[]; // AWS only
  resourceGroup?: string[]; // Azure only
  framework?:     string;   // AWS/Azure only — limits report to one compliance framework
  frameworks?:    string[]; // AWS/Azure only — limits report to multiple compliance frameworks
}

export interface VaptFilterOptionItem {
  id:   string;
  name: string;
}

export interface VaptFilterOptions {
  tags:            string[];
  regions?:        string[]; // AWS only
  resourceGroups?: string[]; // Azure only
  frameworks?:     VaptFilterOptionItem[];
}

function buildQuery(provider: ReportProvider, targetId: string, filters?: VaptReportFilters): string {
  const params = new URLSearchParams({ provider, targetId });
  if (filters?.tags?.length)          params.set('tags', filters.tags.join(','));
  if (filters?.region?.length)        params.set('region', filters.region.join(','));
  if (filters?.resourceGroup?.length) params.set('resourceGroup', filters.resourceGroup.join(','));
  if (filters?.frameworks?.length)    params.set('frameworks', filters.frameworks.join(','));
  else if (filters?.framework)        params.set('framework', filters.framework);
  return params.toString();
}

/**
 * Fetch the VAPT report as raw HTML (authenticated — same access token as the
 * rest of the app) and open it in a new tab via a Blob URL. Blob URL rather than
 * a bare `window.open('/api/...')` because the report route requires the
 * Authorization header, which a plain browser navigation can't attach; using
 * `fetch` + Blob keeps the endpoint properly authenticated instead of relying
 * on a `?token=` query param or an unauthenticated route.
 *
 * The report itself is styled for `@media print`, so "Save as PDF" from the
 * browser's print dialog produces a clean, paginated PDF — no server-side PDF
 * renderer / headless-browser dependency needed.
 */
async function fetchReportHtml(path: string): Promise<string> {
  const { accessToken } = useAuthStore.getState();

  const doFetch = (token: string | null) =>
    fetch(`${BASE_URL}${path}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });

  let response = await doFetch(accessToken);

  if (response.status === 401) {
    const newToken = await refreshAccessToken();
    if (!newToken) throw new ApiRequestError('Unauthorized', 401);
    response = await doFetch(newToken);
  }

  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const body = await response.json() as { error?: string; message?: string };
      message = body.error || body.message || message;
    } catch {
      // response wasn't JSON (e.g. a raw error page) — keep the generic message
    }
    throw new ApiRequestError(message, response.status);
  }

  return response.text();
}

function openHtmlInNewTab(html: string): void {
  const blob = new Blob([html], { type: 'text/html' });
  const url  = URL.createObjectURL(blob);
  const win  = window.open(url, '_blank');
  // Revoke once the new tab has had a chance to load the blob; a short delay
  // is simplest and avoids needing a load-event bridge across the new window.
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
  if (!win) {
    throw new Error('Pop-up blocked — please allow pop-ups for this site to view the report.');
  }
}

const AWS_SVG = `<div style="display:flex;justify-content:center;align-items:center;margin-bottom:20px"><svg height="46" viewBox="-.1 1.1 304.9 179.8" xmlns="http://www.w3.org/2000/svg"><path d="m86.4 66.4c0 3.7.4 6.7 1.1 8.9.8 2.2 1.8 4.6 3.2 7.2.5.8.7 1.6.7 2.3 0 1-.6 2-1.9 3l-6.3 4.2c-.9.6-1.8.9-2.6.9-1 0-2-.5-3-1.4-1.4-1.5-2.6-3.1-3.6-4.7-1-1.7-2-3.6-3.1-5.9-7.8 9.2-17.6 13.8-29.4 13.8-8.4 0-15.1-2.4-20-7.2s-7.4-11.2-7.4-19.2c0-8.5 3-15.4 9.1-20.6s14.2-7.8 24.5-7.8c3.4 0 6.9.3 10.6.8s7.5 1.3 11.5 2.2v-7.3c0-7.6-1.6-12.9-4.7-16-3.2-3.1-8.6-4.6-16.3-4.6-3.5 0-7.1.4-10.8 1.3s-7.3 2-10.8 3.4c-1.6.7-2.8 1.1-3.5 1.3s-1.2.3-1.6.3c-1.4 0-2.1-1-2.1-3.1v-4.9c0-1.6.2-2.8.7-3.5s1.4-1.4 2.8-2.1c3.5-1.8 7.7-3.3 12.6-4.5 4.9-1.3 10.1-1.9 15.6-1.9 11.9 0 20.6 2.7 26.2 8.1 5.5 5.4 8.3 13.6 8.3 24.6v32.4zm-40.6 15.2c3.3 0 6.7-.6 10.3-1.8s6.8-3.4 9.5-6.4c1.6-1.9 2.8-4 3.4-6.4s1-5.3 1-8.7v-4.2c-2.9-.7-6-1.3-9.2-1.7s-6.3-.6-9.4-.6c-6.7 0-11.6 1.3-14.9 4s-4.9 6.5-4.9 11.5c0 4.7 1.2 8.2 3.7 10.6 2.4 2.5 5.9 3.7 10.5 3.7zm80.3 10.8c-1.8 0-3-.3-3.8-1-.8-.6-1.5-2-2.1-3.9l-23.5-77.3c-.6-2-.9-3.3-.9-4 0-1.6.8-2.5 2.4-2.5h9.8c1.9 0 3.2.3 3.9 1 .8.6 1.4 2 2 3.9l16.8 66.2 15.6-66.2c.5-2 1.1-3.3 1.9-3.9s2.2-1 4-1h8c1.9 0 3.2.3 4 1 .8.6 1.5 2 1.9 3.9l15.8 67 17.3-67c.6-2 1.3-3.3 2-3.9.8-.6 2.1-1 3.9-1h9.3c1.6 0 2.5.8 2.5 2.5 0 .5-.1 1-.2 1.6s-.3 1.4-.7 2.5l-24.1 77.3c-.6 2-1.3 3.3-2.1 3.9s-2.1 1-3.8 1h-8.6c-1.9 0-3.2-.3-4-1s-1.5-2-1.9-4l-15.5-64.5-15.4 64.4c-.5 2-1.1 3.3-1.9 4s-2.2 1-4 1zm128.5 2.7c-5.2 0-10.4-.6-15.4-1.8s-8.9-2.5-11.5-4c-1.6-.9-2.7-1.9-3.1-2.8s-.6-1.9-.6-2.8v-5.1c0-2.1.8-3.1 2.3-3.1.6 0 1.2.1 1.8.3s1.5.6 2.5 1c3.4 1.5 7.1 2.7 11 3.5 4 .8 7.9 1.2 11.9 1.2 6.3 0 11.2-1.1 14.6-3.3s5.2-5.4 5.2-9.5c0-2.8-.9-5.1-2.7-7s-5.2-3.6-10.1-5.2l-14.5-4.5c-7.3-2.3-12.7-5.7-16-10.2-3.3-4.4-5-9.3-5-14.5 0-4.2.9-7.9 2.7-11.1s4.2-6 7.2-8.2c3-2.3 6.4-4 10.4-5.2s8.2-1.7 12.6-1.7c2.2 0 4.5.1 6.7.4 2.3.3 4.4.7 6.5 1.1 2 .5 3.9 1 5.7 1.6s3.2 1.2 4.2 1.8c1.4.8 2.4 1.6 3 2.5.6.8.9 1.9.9 3.3v4.7c0 2.1-.8 3.2-2.3 3.2-.8 0-2.1-.4-3.8-1.2-5.7-2.6-12.1-3.9-19.2-3.9-5.7 0-10.2.9-13.3 2.8s-4.7 4.8-4.7 8.9c0 2.8 1 5.2 3 7.1s5.7 3.8 11 5.5l14.2 4.5c7.2 2.3 12.4 5.5 15.5 9.6s4.6 8.8 4.6 14c0 4.3-.9 8.2-2.6 11.6-1.8 3.4-4.2 6.4-7.3 8.8-3.1 2.5-6.8 4.3-11.1 5.6-4.5 1.4-9.2 2.1-14.3 2.1z" fill="#252f3e"/><g clip-rule="evenodd" fill="#f90" fill-rule="evenodd"><path d="m273.5 143.7c-32.9 24.3-80.7 37.2-121.8 37.2-57.6 0-109.5-21.3-148.7-56.7-3.1-2.8-.3-6.6 3.4-4.4 42.4 24.6 94.7 39.5 148.8 39.5 36.5 0 76.6-7.6 113.5-23.2 5.5-2.5 10.2 3.6 4.8 7.6z"/><path d="m287.2 128.1c-4.2-5.4-27.8-2.6-38.5-1.3-3.2.4-3.7-2.4-.8-4.5 18.8-13.2 49.7-9.4 53.3-5 3.6 4.5-1 35.4-18.6 50.2-2.7 2.3-5.3 1.1-4.1-1.9 4-9.9 12.9-32.2 8.7-37.5z"/></g></svg></div>`;
const AZURE_SVG = `<div style="display:flex;justify-content:center;align-items:center;margin-bottom:20px"><svg height="42" xmlns="http://www.w3.org/2000/svg" viewBox="-0.45 0.38 800.88 754.22"><linearGradient id="a" gradientUnits="userSpaceOnUse" x1="353.1" x2="107.1" y1="56.3" y2="783"><stop offset="0" stop-color="#114a8b"/><stop offset="1" stop-color="#0669bc"/></linearGradient><linearGradient id="b" gradientUnits="userSpaceOnUse" x1="429.8" x2="372.9" y1="394.9" y2="414.2"><stop offset="0" stop-opacity=".3"/><stop offset=".1" stop-opacity=".2"/><stop offset=".3" stop-opacity=".1"/><stop offset=".6" stop-opacity=".1"/><stop offset="1" stop-opacity="0"/></linearGradient><linearGradient id="c" gradientUnits="userSpaceOnUse" x1="398.4" x2="668.4" y1="35.1" y2="754.4"><stop offset="0" stop-color="#3ccbf4"/><stop offset="1" stop-color="#2892df"/></linearGradient><path d="M266.71.4h236.71L257.69 728.9a37.8 37.8 0 0 1-5.42 10.38c-2.33 3.16-5.14 5.93-8.33 8.22s-6.71 4.07-10.45 5.27-7.64 1.82-11.56 1.82H37.71c-5.98 0-11.88-1.42-17.2-4.16A37.636 37.636 0 0 1 7.1 738.87a37.762 37.762 0 0 1-6.66-16.41c-.89-5.92-.35-11.97 1.56-17.64L230.94 26.07c1.25-3.72 3.08-7.22 5.42-10.38 2.33-3.16 5.15-5.93 8.33-8.22 3.19-2.29 6.71-4.07 10.45-5.27S262.78.38 266.7.38v.01z" fill="url(#a)"/><path d="M703.07 754.59H490.52c-2.37 0-4.74-.22-7.08-.67-2.33-.44-4.62-1.1-6.83-1.97s-4.33-1.95-6.34-3.21a38.188 38.188 0 0 1-5.63-4.34l-241.2-225.26a17.423 17.423 0 0 1-5.1-8.88 17.383 17.383 0 0 1 7.17-18.21c2.89-1.96 6.3-3.01 9.79-3.01h375.36l92.39 265.56z" fill="#0078d4"/><path d="M504.27.4l-165.7 488.69 270.74-.06 92.87 265.56H490.43c-2.19-.02-4.38-.22-6.54-.61s-4.28-.96-6.34-1.72a38.484 38.484 0 0 1-11.36-6.51L303.37 593.79l-45.58 134.42c-1.18 3.36-2.8 6.55-4.82 9.48a40.479 40.479 0 0 1-16.05 13.67 40.03 40.03 0 0 1-10.13 3.23H37.82c-6.04.02-12-1.42-17.37-4.2A37.664 37.664 0 0 1 .43 722a37.77 37.77 0 0 1 1.87-17.79L230.87 26.58c1.19-3.79 2.98-7.36 5.3-10.58 2.31-3.22 5.13-6.06 8.33-8.4s6.76-4.16 10.53-5.38S262.75.38 266.72.4h237.56z" fill="url(#b)"/><path d="M797.99 704.82a37.847 37.847 0 0 1 1.57 17.64 37.867 37.867 0 0 1-6.65 16.41 37.691 37.691 0 0 1-30.61 15.72H498.48c5.98 0 11.88-1.43 17.21-4.16 5.32-2.73 9.92-6.7 13.41-11.56s5.77-10.49 6.66-16.41.35-11.97-1.56-17.64L305.25 26.05a37.713 37.713 0 0 0-13.73-18.58c-3.18-2.29-6.7-4.06-10.43-5.26S273.46.4 269.55.4h263.81c3.92 0 7.81.61 11.55 1.81 3.73 1.2 7.25 2.98 10.44 5.26 3.18 2.29 5.99 5.06 8.32 8.21s4.15 6.65 5.41 10.37l228.95 678.77z" fill="url(#c)"/></svg></div>`;
const GCP_SVG = `<div style="display:flex;justify-content:center;align-items:center;margin-bottom:20px"><svg height="42" viewBox="0 0 467 467" xmlns="http://www.w3.org/2000/svg"><path d="M467 238.5c0-16-1.5-31.5-4.2-46.5H238.5v88.2h128.5c-5.5 29.8-22.3 55-47.5 71.8v59.7h76.8C441.2 369.8 467 309.2 467 238.5z" fill="#4285F4"/><path d="M238.5 467c61.7 0 113.5-20.5 151.3-55.3l-76.8-59.7c-20.5 13.7-46.7 21.8-74.5 21.8-57.3 0-105.8-38.7-123.1-90.8H36.3v61.7C74.3 420 150.8 467 238.5 467z" fill="#34A853"/><path d="M115.4 283c-4.4-13.2-6.9-27.3-6.9-44.5s2.5-31.3 6.9-44.5v-61.7H36.3C13.2 178.5 0 207 0 238.5s13.2 60 36.3 106.2l79.1-61.7z" fill="#FBBC05"/><path d="M238.5 91.3c33.5 0 63.5 11.5 87.2 34.2l65.4-65.4C351.8 22.3 300 0 238.5 0 150.8 0 74.3 47 36.3 122.3l79.1 61.7c17.3-52.1 65.8-92.7 123.1-92.7z" fill="#EA4335"/></svg></div>`;

const FRAMEWORK_DISPLAY_NAMES: Record<string, { shortName: string; fullName: string }> = {
  PCI_DSS:     { shortName: 'PCI DSS', fullName: 'PCI DSS' },
  SOC2:        { shortName: 'SOC 2', fullName: 'SOC 2' },
  ISO27001:    { shortName: 'ISO 27001', fullName: 'ISO/IEC 27001' },
  HIPAA:       { shortName: 'HIPAA', fullName: 'HIPAA' },
  CIS_AWS:     { shortName: 'CIS AWS', fullName: 'CIS AWS Foundations' },
  CIS_AZURE:   { shortName: 'CIS Azure', fullName: 'CIS Microsoft Azure' },
  NIST_800_53: { shortName: 'NIST 800-53', fullName: 'NIST' },
  NIST:        { shortName: 'NIST', fullName: 'NIST' },
  GDPR:        { shortName: 'GDPR', fullName: 'GDPR' },
  FEDRAMP:     { shortName: 'FedRAMP', fullName: 'FedRAMP' },
};

function applyClientSideFrameworkFilter(html: string, frameworkIds: string[]): string {
  if (!frameworkIds || frameworkIds.length === 0) return html;
  if (typeof DOMParser === 'undefined') return html;

  const selectedMetas = frameworkIds
    .map(id => FRAMEWORK_DISPLAY_NAMES[id])
    .filter(Boolean);

  if (selectedMetas.length === 0) return html;

  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');

  const matchesSelected = (text: string) => {
    const t = text.toLowerCase();
    return selectedMetas.some(meta => 
      t.includes(meta.shortName.toLowerCase()) || 
      t.includes(meta.fullName.toLowerCase())
    );
  };

  // 1. Filter Gauges inside .gauge-grid
  const gaugeGrid = doc.querySelector('.gauge-grid');
  if (gaugeGrid) {
    const gauges = Array.from(gaugeGrid.querySelectorAll('.gauge'));
    for (const gauge of gauges) {
      if (!matchesSelected(gauge.textContent || '')) {
        gauge.remove();
      }
    }
  }

  // 2. Filter Overview Table Rows
  const tables = Array.from(doc.querySelectorAll('table'));
  for (const table of tables) {
    const rows = Array.from(table.querySelectorAll('tbody tr'));
    if (rows.length > 0) {
      for (const row of rows) {
        if (!matchesSelected(row.textContent || '')) {
          row.remove();
        }
      }
    }
  }

  // 3. Filter Detailed Findings (.finding-card)
  const findingCards = Array.from(doc.querySelectorAll('.finding-card'));
  for (const card of findingCards) {
    const chips = Array.from(card.querySelectorAll('.compliance-chip')).map(c => (c.textContent || '').trim().toLowerCase());
    const cardText = (card.textContent || '').toLowerCase();

    const matches = selectedMetas.some(meta => {
      const s = meta.shortName.toLowerCase();
      const f = meta.fullName.toLowerCase();
      return chips.some(chip => chip.includes(s) || chip.includes(f)) ||
             cardText.includes(s) ||
             cardText.includes(f);
    });

    if (!matches) {
      card.remove();
    }
  }

  // 4. Remove empty severity groups (.severity-group) & update group counts
  const sevGroups = Array.from(doc.querySelectorAll('.severity-group'));
  for (const group of sevGroups) {
    const remainingCards = group.querySelectorAll('.finding-card');
    if (remainingCards.length === 0) {
      group.remove();
    } else {
      const countEl = group.querySelector('.sev-group-title .count');
      if (countEl) {
        countEl.textContent = `(${remainingCards.length})`;
      }
    }
  }

  // 5. Update Executive Summary Stat Cards
  const remainingFindingCards = Array.from(doc.querySelectorAll('.finding-card'));
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: remainingFindingCards.length };

  for (const card of remainingFindingCards) {
    const badge = card.querySelector('.sev-badge')?.textContent?.trim().toLowerCase() || '';
    if (badge in counts) {
      counts[badge as keyof typeof counts]++;
    }
  }

  const setStatVal = (selector: string, val: number) => {
    const el = doc.querySelector(selector);
    if (el) el.textContent = String(val);
  };

  setStatVal('.stat-card.critical .stat-val', counts.critical);
  setStatVal('.stat-card.high .stat-val', counts.high);
  setStatVal('.stat-card.medium .stat-val', counts.medium);
  setStatVal('.stat-card.low .stat-val', counts.low);
  setStatVal('.stat-card.info .stat-val', counts.info);
  setStatVal('.stat-card.total .stat-val', counts.total);

  // 6. Update cover filter banner
  const confidentialEl = doc.querySelector('.cover-confidential');
  if (confidentialEl && !doc.querySelector('.cover-filters')) {
    const labelsStr = selectedMetas.map(m => m.fullName).join(', ');
    const bannerDiv = doc.createElement('div');
    bannerDiv.className = 'cover-filters';
    bannerDiv.innerHTML = `
      <span class="cover-filters-label">FILTERED REPORT &mdash; DOES NOT COVER FULL TARGET</span>
      <span class="cover-filters-val">Framework${selectedMetas.length > 1 ? 's' : ''}: ${labelsStr}</span>
    `;
    confidentialEl.parentNode?.insertBefore(bannerDiv, confidentialEl);
  }

  return '<!DOCTYPE html>\n' + doc.documentElement.outerHTML;
}

function transformReportHtml(html: string, provider: ReportProvider, filters?: VaptReportFilters): string {
  let updated = html;

  const activeFws = filters?.frameworks?.length 
    ? filters.frameworks 
    : filters?.framework 
      ? [filters.framework] 
      : [];

  if (activeFws.length > 0) {
    updated = applyClientSideFrameworkFilter(updated, activeFws);
  }

  const logoSvg = provider === 'AWS' ? AWS_SVG : provider === 'AZURE' ? AZURE_SVG : GCP_SVG;

  // Replace cover badge with transparent SVG logo
  updated = updated.replace(/<div class="cover-badge"[^>]*>[\s\S]*?<\/div>/gi, logoSvg);

  // Replace CONFIDENTIAL text exactly as requested
  updated = updated.replace(
    /CONFIDENTIAL &nbsp;&middot;&nbsp; Prepared for authorized recipients only\. Distribution outside the intended audience is strictly prohibited\./gi,
    'CONFIDENTIAL &mdash; Prepared for authorized recipients only. Distribution outside the intended audience is prohibited.'
  );

  // Inject top-right watermark logo for the company
  const logoUrl = `${typeof window !== 'undefined' ? window.location.origin : ''}/img/logo.png`;
  updated = updated.replace(
    /<div class="cover"[^>]*>/i,
    `$&\n  <div class="watermark-top-right"><img src="${logoUrl}" alt="Logo" class="watermark-logo-img" /></div>`
  );

  // Inject Google Fonts Inter & JetBrains Mono + modern typography CSS if missing
  const fonts = `<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
<style>
  body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important; }
  .mono { font-family: 'JetBrains Mono', monospace !important; }
  .stat { border-top: 4px solid #0f172a !important; border-radius: 12px !important; }
  .stat-val.critical, .stat-val.critical-val { color: #dc2626 !important; }
  .stat-val.high { color: #ea580c !important; }
  .stat-val.medium { color: #d97706 !important; }
  .stat-val.low { color: #2563eb !important; }
  .gauge-grid { display: flex !important; flex-wrap: wrap !important; justify-content: flex-start !important; gap: 24px !important; margin-bottom: 24px !important; }
  .gauge { flex: 0 0 auto !important; width: 96px !important; }

  /* Cover overrides */
  .cover { position: relative !important; }
  .watermark-top-right { position: absolute !important; top: 24px !important; right: 60px !important; display: flex !important; align-items: center !important; }
  .watermark-logo-img { height: 53px !important; max-width: 230px !important; object-fit: contain !important; }
  .cover-title { font-size: 34px !important; margin-bottom: 16px !important; }
  .cover-target { font-size: 24px !important; font-weight: 700 !important; margin-bottom: 8px !important; }
  .cover-id { margin-bottom: 48px !important; }
  .cover-confidential { white-space: nowrap !important; font-size: 11.5px !important; font-style: italic !important; margin-top: 24px !important; }
  .meta-card { box-shadow: none !important; border: none !important; background: transparent !important; }
  .meta-label { font-size: 11px !important; }
  .meta-val { font-size: 15px !important; }
  .risk-badge { font-size: 15px !important; }

  /* IAM Users overrides */
  .iam-row-flagged { background: transparent !important; }
  .iam-row-flagged td:first-child { box-shadow: inset 4px 0 0 #dc2626 !important; }
  .open-ended-badge { background: transparent !important; color: #dc2626 !important; font-weight: 800 !important; border: none !important; padding: 0 !important; white-space: normal !important; }
  .iam-detail-cell { line-height: 1.6 !important; font-size: 11.5px !important; max-width: 320px !important; }
  .iam-detail-cell div { margin-bottom: 8px !important; }
  .iam-detail-cell strong { display: block !important; font-size: 9.5px !important; text-transform: uppercase !important; letter-spacing: 0.05em !important; color: #94a3b8 !important; margin-bottom: 4px !important; }
  .policy-chip { background: #f8fafc !important; border: 1px solid #e2e8f0 !important; padding: 4px 8px !important; margin-bottom: 4px !important; display: inline-block !important; max-width: 100% !important; white-space: normal !important; word-break: break-all !important; }
  .policy-chip-admin { background: #fff1f2 !important; color: #be123c !important; border-color: #fecdd3 !important; }
  td { padding: 16px !important; }
  th { padding: 12px 16px !important; }
</style>`;

  if (!updated.includes('fonts.googleapis.com')) {
    updated = updated.replace('</head>', `${fonts}\n</head>`);
  }

  return updated;
}

export const reportsApi = {
  /** Generate + open the professional VAPT-style report for one account/subscription/project. */
  openVaptReport: async (provider: ReportProvider, targetId: string, filters?: VaptReportFilters): Promise<void> => {
    const rawHtml = await fetchReportHtml(`/reports/vapt?${buildQuery(provider, targetId, filters)}`);
    const transformedHtml = transformReportHtml(rawHtml, provider, filters);
    openHtmlInNewTab(transformedHtml);
  },

  /** Real distinct tag/region/resource-group values available for this target's open findings. */
  getVaptFilterOptions: (provider: ReportProvider, targetId: string) =>
    api.get<VaptFilterOptions>(`/reports/vapt/filters?provider=${provider}&targetId=${targetId}`),
};
