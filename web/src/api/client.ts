import { useAuthStore } from '../store/authStore';

const BASE_URL = '/api/cspm';

interface ApiError {
  message?: string;
  error?: string;
  status?: number;
}

export class ApiRequestError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
    this.name = 'ApiRequestError';
  }
}

let isRefreshing = false;
let refreshPromise: Promise<string | null> | null = null;

export async function refreshAccessToken(): Promise<string | null> {
  const { refreshToken, setTokens, logout } = useAuthStore.getState();
  if (!refreshToken) {
    logout();
    return null;
  }

  try {
    const response = await fetch(`${BASE_URL}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
    });

    if (!response.ok) {
      logout();
      return null;
    }

    const json = await response.json() as { data: { accessToken: string; refreshToken: string } } | { accessToken: string; refreshToken: string };
    const data = 'data' in json ? json.data : json;
    setTokens({ accessToken: data.accessToken, refreshToken: data.refreshToken });
    return data.accessToken;
  } catch {
    logout();
    return null;
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const { accessToken } = useAuthStore.getState();

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  const config: RequestInit = {
    method,
    headers,
  };

  if (body !== undefined) {
    config.body = JSON.stringify(body);
  }

  let response = await fetch(`${BASE_URL}${path}`, config);

  if (response.status === 401) {
    // Try to refresh token
    if (!isRefreshing) {
      isRefreshing = true;
      refreshPromise = refreshAccessToken().finally(() => {
        isRefreshing = false;
        refreshPromise = null;
      });
    }

    const newToken = await refreshPromise;

    if (newToken) {
      // Retry the original request with new token
      const retryHeaders: Record<string, string> = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${newToken}`,
      };

      response = await fetch(`${BASE_URL}${path}`, {
        ...config,
        headers: retryHeaders,
      });
    } else {
      throw new ApiRequestError('Unauthorized', 401);
    }
  }

  if (!response.ok) {
    let errorMessage = `HTTP ${response.status}`;
    try {
      const errorData = await response.json() as ApiError;
      errorMessage = errorData.error || errorData.message || errorMessage;
    } catch {
      // Ignore JSON parse errors for error responses
    }
    throw new ApiRequestError(errorMessage, response.status);
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return undefined as unknown as T;
  }

  try {
    const json = await response.json() as Record<string, unknown>;
    // Paginated response: { data: [...], meta: {...} } → merge into flat object
    if (json !== null && typeof json === 'object' && 'data' in json && 'meta' in json) {
      const meta = json.meta as Record<string, unknown>;
      return { data: json.data, ...meta, pageSize: meta.limit ?? meta.pageSize } as T;
    }
    // Standard envelope: { data: ... } → unwrap
    if (json !== null && typeof json === 'object' && 'data' in json) {
      return json.data as T;
    }
    return json as T;
  } catch {
    return undefined as unknown as T;
  }
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body),
  patch: <T>(path: string, body?: unknown) => request<T>('PATCH', path, body),
  delete: <T>(path: string) => request<T>('DELETE', path),
};
