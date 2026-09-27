import { Request, Response, NextFunction } from 'express';
import { prisma } from '../config/database';
import { logger } from '../config/logger';

/**
 * User-action audit trail.
 *
 * Records every state-changing request (POST/PUT/PATCH/DELETE) under /api,
 * plus any request that was denied (401/403), after the response finishes.
 * Reads are not recorded to keep the table small; use access logs for those.
 *
 * Bodies are stored with secrets redacted (see REDACT_KEYS) and truncated.
 * Writes are fire-and-forget: an audit insert failure is logged but never
 * blocks or fails the user's request.
 */

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const MAX_BODY_CHARS = 4_000;

const REDACT_KEYS =
  /(password|passwd|secret|token|apikey|api_key|accesskey|access_key|privatekey|private_key|credential|clientsecret|client_secret|authorization|serviceaccountkey)/i;

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 6) return '[depth]';
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = REDACT_KEYS.test(k) ? '[REDACTED]' : redact(v, depth + 1);
    }
    return out;
  }
  return value;
}

function serializeBody(body: unknown): string | null {
  if (body === undefined || body === null) return null;
  if (typeof body === 'object' && Object.keys(body as object).length === 0) return null;
  try {
    const s = JSON.stringify(redact(body));
    return s.length > MAX_BODY_CHARS ? s.slice(0, MAX_BODY_CHARS) + '...' : s;
  } catch {
    return null;
  }
}

const COLLECTION_VERBS = new Set([
  'login', 'logout', 'refresh', 'setup', 'deduplicate', 'sync', 'discover', 'compute',
  'backfill', 'collect', 'export', 'scan', 'seed', 'reconcile-inventory', 'bulk-status',
  'cleanup-scanner-errors', 'compile', 'build', 'test',
]);

/** "accounts.create", "findings.update", "auth.login", "approvals.approve" ... */
export function deriveAction(method: string, path: string): string {
  const segments = path.split('?')[0].split('/').filter(Boolean);
  const resource = (segments[0] ?? 'root').replace(/-/g, '_');
  const last = segments[segments.length - 1] ?? '';
  const verbFromMethod: Record<string, string> = {
    POST: 'create',
    PUT: 'update',
    PATCH: 'update',
    DELETE: 'delete',
    GET: 'read',
  };
  // Sub-actions (/scan, /approve, /run, /revert, /login) are more useful than
  // the bare method. A trailing word is a sub-action when it follows an id
  // (odd segment count: resource/id/verb, resource/id/sub/id/verb) or is a
  // known collection-level verb (resource/verb). Plain ids never match.
  const isSubAction =
    segments.length > 1 &&
    /^[a-z][a-z-]*$/.test(last) &&
    last !== segments[0] &&
    (segments.length % 2 === 1 || COLLECTION_VERBS.has(last));
  const verb = isSubAction ? last.replace(/-/g, '_') : verbFromMethod[method.toUpperCase()] ?? method.toLowerCase();
  return `${resource}.${verb}`;
}

function firstIp(req: Request): string | null {
  const fwd = req.headers['x-forwarded-for'];
  const raw = Array.isArray(fwd) ? fwd[0] : fwd?.split(',')[0];
  const ip = (raw ?? req.ip ?? '').trim();
  return ip || null;
}

/**
 * Mount on '/api' BEFORE `authenticate` so login attempts and denied requests
 * are captured; `req.user` is read at response time, after downstream
 * middleware has set it.
 */
export function auditLog(req: Request, res: Response, next: NextFunction): void {
  const startedAt = Date.now();
  const method = req.method.toUpperCase();
  const path = req.path;

  res.on('finish', () => {
    const denied = res.statusCode === 401 || res.statusCode === 403;
    if (!MUTATING.has(method) && !denied) return;
    // Silent token refresh is not a user action; only record it when it fails.
    if (method === 'POST' && path === '/auth/refresh' && res.statusCode < 400) return;

    const body = req.body as Record<string, unknown> | undefined;
    const actorEmail = path.startsWith('/auth/') && typeof body?.email === 'string' ? body.email : null;

    prisma.auditLog
      .create({
        data: {
          userId: req.user?.id ?? null,
          userRole: req.user?.role ?? null,
          actorEmail,
          action: deriveAction(method, path),
          method,
          path: `/api${path}`,
          query: Object.keys(req.query ?? {}).length ? serializeBody(req.query) : null,
          statusCode: res.statusCode,
          outcome: res.statusCode < 400 ? 'SUCCESS' : denied ? 'DENIED' : 'FAILED',
          ip: firstIp(req),
          userAgent: String(req.headers['user-agent'] ?? '').slice(0, 300) || null,
          requestBody: serializeBody(body),
          durationMs: Date.now() - startedAt,
        },
      })
      .catch((err: Error) => logger.warn(`[audit] failed to record ${method} ${path}: ${err.message}`));
  });

  next();
}

export default auditLog;
