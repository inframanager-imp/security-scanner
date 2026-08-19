import { useAuthStore } from '../store/authStore';
import { refreshAccessToken, ApiRequestError, api } from './client';

const BASE_URL = '/api/cspm';

export type ReportProvider = 'AWS' | 'AZURE' | 'GCP';

export interface VaptReportFilters {
  tags?:          string[]; // all providers — OR-match (finding has ANY of these tags)
  region?:        string[]; // AWS only
  resourceGroup?: string[]; // Azure only
}

export interface VaptFilterOptions {
  tags:            string[];
  regions?:        string[]; // AWS only
  resourceGroups?: string[]; // Azure only
}

function buildQuery(provider: ReportProvider, targetId: string, filters?: VaptReportFilters): string {
  const params = new URLSearchParams({ provider, targetId });
  if (filters?.tags?.length)          params.set('tags', filters.tags.join(','));
  if (filters?.region?.length)        params.set('region', filters.region.join(','));
  if (filters?.resourceGroup?.length) params.set('resourceGroup', filters.resourceGroup.join(','));
  return params.toString();
}

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
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
  if (!win) {
    throw new Error('Pop-up blocked — please allow pop-ups for this site to view the report.');
  }
}

export const reportsApi = {
  /** Generate + open the professional VAPT-style report for one account/subscription/project. */
  openVaptReport: async (provider: ReportProvider, targetId: string, filters?: VaptReportFilters): Promise<void> => {
    const html = await fetchReportHtml(`/reports/vapt?${buildQuery(provider, targetId, filters)}`);
    openHtmlInNewTab(html);
  },

  /** Real distinct tag/region/resource-group values available for this target's open findings. */
  getVaptFilterOptions: (provider: ReportProvider, targetId: string) =>
    api.get<VaptFilterOptions>(`/reports/vapt/filters?provider=${provider}&targetId=${targetId}`),
};
