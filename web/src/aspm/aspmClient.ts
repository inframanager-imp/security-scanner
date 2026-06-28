// Auth shim for the ASPM (Python) backend. The ASPM views use raw fetch / streaming
// reads and window.open; this injects the CSPM-issued JWT so the unified login also
// authorizes /api/aspm/* calls.
import { useAuthStore } from '../store/authStore';
import { refreshAccessToken } from '../api/client';

function getToken(): string | null {
  try {
    return useAuthStore.getState().accessToken;
  } catch {
    return null;
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Transient gateway statuses that mean "backend momentarily unavailable"
// (e.g. the aspm-api container is restarting/rebuilding). Safe to retry.
const TRANSIENT = new Set([502, 503, 504]);

/**
 * fetch() wrapper that adds the Bearer token and rides through transient backend
 * outages: on a network error or 502/503/504 it retries with backoff, so a
 * container restart never surfaces as a blank page. Streaming reads work too.
 */
export async function aspmFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const attempts = 4;
  let lastErr: unknown;
  let triedRefresh = false;

  for (let i = 0; i < attempts; i++) {
    // Read the (possibly just-refreshed) token on every attempt.
    const token = getToken();
    const headers = new Headers(init.headers || {});
    if (token) headers.set('Authorization', `Bearer ${token}`);

    try {
      const res = await fetch(input, { ...init, headers });

      // Access token expired → refresh once (shared with CSPM) and retry.
      if (res.status === 401 && token && !triedRefresh) {
        triedRefresh = true;
        const newToken = await refreshAccessToken();
        if (newToken) {
          i--; // don't consume a retry slot
          continue;
        }
        return res; // refresh failed → caller/logout handles it
      }

      // Backend momentarily unavailable (restart/rebuild) → backoff + retry.
      if (TRANSIENT.has(res.status) && i < attempts - 1) {
        await sleep(700 * (i + 1)); // 0.7s, 1.4s, 2.1s
        continue;
      }
      return res;
    } catch (err) {
      lastErr = err;
      if (i < attempts - 1) {
        await sleep(700 * (i + 1));
        continue;
      }
      throw err;
    }
  }
  throw lastErr;
}

/** Append the token as a query param — for window.open()/downloads that can't set headers. */
export function aspmUrl(url: string): string {
  const token = getToken();
  if (!token) return url;
  return url + (url.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(token);
}
