import { Request, Response, NextFunction } from 'express';

/**
 * Central role-based access policy for every /api route.
 *
 * Roles: ADMIN > ANALYST > VIEWER.
 *   - VIEWER  can read everything (GET/HEAD) and nothing else.
 *   - ANALYST can additionally run scans, triage findings, manage baselines,
 *             risk items, evidence, and other day-to-day operational actions.
 *   - ADMIN   can do everything, including anything that changes credentials,
 *             onboarding, integrations, alerting, scheduling, or destroys data.
 *
 * Rules are evaluated top-down; the first match wins. Paths are matched
 * against `req.path` relative to the `/api` mount (e.g. "/accounts/abc").
 * Anything not matched falls through to the method-based default:
 *   GET/HEAD/OPTIONS -> any authenticated role, otherwise ANALYST or ADMIN.
 *
 * Keep this table in sync with docs/api/rbac.md.
 */

export type Role = 'ADMIN' | 'ANALYST' | 'VIEWER';

export const ALL_ROLES: Role[] = ['ADMIN', 'ANALYST', 'VIEWER'];
export const OPERATORS: Role[] = ['ADMIN', 'ANALYST'];
export const ADMIN_ONLY: Role[] = ['ADMIN'];

export interface PolicyRule {
  /** HTTP methods this rule applies to; '*' for any. */
  methods: string[] | '*';
  /** Regex tested against the path relative to /api. */
  path: RegExp;
  roles: Role[];
  /** Human-readable purpose, surfaced in docs/tests. */
  description: string;
}

const MUTATING = ['POST', 'PUT', 'PATCH', 'DELETE'];
const ID = '[^/]+';

export const POLICY_RULES: PolicyRule[] = [
  // ── Audit log: admin only, even for reads ────────────────────────────────
  { methods: '*', path: /^\/audit-logs(\/|$)/, roles: ADMIN_ONLY, description: 'Audit log is admin-only' },

  // ── Cloud target onboarding & credentials (AWS / Azure / GCP) ────────────
  { methods: ['POST'], path: /^\/accounts\/setup$/, roles: ADMIN_ONLY, description: 'Initial AWS setup' },
  { methods: ['POST'], path: /^\/(accounts|azure\/subscriptions|gcp\/projects)$/, roles: ADMIN_ONLY, description: 'Onboard a cloud target' },
  { methods: ['PUT', 'DELETE'], path: new RegExp(`^/(accounts|azure/subscriptions|gcp/projects)/${ID}$`), roles: ADMIN_ONLY, description: 'Edit or remove a cloud target' },
  { methods: '*', path: new RegExp(`^/(accounts|azure/subscriptions|gcp/projects)/${ID}/credentials(/|$)`), roles: ADMIN_ONLY, description: 'Manage cloud credentials' },
  { methods: ['POST'], path: new RegExp(`^/(azure/subscriptions|gcp/projects)/${ID}/scan$`), roles: OPERATORS, description: 'Trigger a scan' },

  // ── Scans & findings ─────────────────────────────────────────────────────
  { methods: ['DELETE'], path: new RegExp(`^/scans/${ID}$`), roles: ADMIN_ONLY, description: 'Delete a scan and its findings' },
  { methods: ['POST'], path: /^\/findings\/deduplicate$/, roles: ADMIN_ONLY, description: 'Destructive finding cleanup' },
  { methods: ['DELETE'], path: /^\/azure\/scans\/findings\/cleanup-scanner-errors$/, roles: ADMIN_ONLY, description: 'Destructive finding cleanup' },

  // ── Platform configuration: integrations, alerting, freeze windows ───────
  { methods: MUTATING, path: /^\/(integrations|alerts|freeze-windows)(\/|$)/, roles: ADMIN_ONLY, description: 'Platform configuration' },

  // ── Scheduled reports ────────────────────────────────────────────────────
  { methods: ['POST'], path: new RegExp(`^/report-schedules/${ID}/run$`), roles: OPERATORS, description: 'Run a report on demand' },
  { methods: MUTATING, path: /^\/report-schedules(\/|$)/, roles: ADMIN_ONLY, description: 'Manage report schedules' },

  // ── Change control: approvals & baselines ────────────────────────────────
  { methods: ['POST'], path: new RegExp(`^/approvals/${ID}/(approve|reject)$`), roles: ADMIN_ONLY, description: 'Decide an approval request' },
  { methods: ['DELETE'], path: new RegExp(`^/approvals/${ID}$`), roles: ADMIN_ONLY, description: 'Delete an approval request' },
  { methods: ['DELETE'], path: new RegExp(`^/baselines/${ID}$`), roles: ADMIN_ONLY, description: 'Delete a baseline' },
  { methods: ['POST'], path: new RegExp(`^/baselines/${ID}/drift/${ID}/revert$`), roles: ADMIN_ONLY, description: 'Auto-revert live cloud config' },

  // ── Compliance evidence & anomaly baselines ──────────────────────────────
  { methods: ['DELETE'], path: new RegExp(`^/compliance/evidence/${ID}$`), roles: ADMIN_ONLY, description: 'Delete compliance evidence' },
  { methods: ['DELETE', 'POST'], path: /^\/anomaly\/baselines(\/seed)?$/, roles: ADMIN_ONLY, description: 'Reset or seed anomaly baselines' },
];

export function rolesAllowedFor(method: string, path: string): Role[] {
  const m = method.toUpperCase();
  for (const rule of POLICY_RULES) {
    if (rule.methods !== '*' && !rule.methods.includes(m)) continue;
    if (rule.path.test(path)) return rule.roles;
  }
  return m === 'GET' || m === 'HEAD' || m === 'OPTIONS' ? ALL_ROLES : OPERATORS;
}

export function isAllowed(role: string | undefined, method: string, path: string): boolean {
  if (!role) return false;
  return (rolesAllowedFor(method, path) as string[]).includes(role);
}

/**
 * Express middleware. Mount on '/api' AFTER `authenticate` so `req.user` is set.
 */
export function rbacPolicy(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ error: 'No token provided' });
    return;
  }
  if (!isAllowed(req.user.role, req.method, req.path)) {
    res.status(403).json({
      error: 'Forbidden',
      detail: `Role ${req.user.role} may not ${req.method} ${req.path}`,
    });
    return;
  }
  next();
}

export default rbacPolicy;
