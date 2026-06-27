// Auth shim for the ASPM (Python) backend. The ASPM views use raw fetch / streaming
// reads and window.open; this injects the CSPM-issued JWT so the unified login also
// authorizes /api/aspm/* calls.
import { useAuthStore } from '../store/authStore';

function getToken(): string | null {
  try {
    return useAuthStore.getState().accessToken;
  } catch {
    return null;
  }
}

/** fetch() wrapper that adds the Bearer token (works for streaming reads too). */
export function aspmFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const token = getToken();
  const headers = new Headers(init.headers || {});
  if (token) headers.set('Authorization', `Bearer ${token}`);
  return fetch(input, { ...init, headers });
}

/** Append the token as a query param — for window.open()/downloads that can't set headers. */
export function aspmUrl(url: string): string {
  const token = getToken();
  if (!token) return url;
  return url + (url.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(token);
}
