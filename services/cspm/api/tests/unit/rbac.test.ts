import { rolesAllowedFor, isAllowed, POLICY_RULES } from '../../src/middleware/rbac';

describe('rbac policy', () => {
  const cases: Array<[string, string, string[]]> = [
    // reads are open to every role
    ['GET', '/accounts', ['ADMIN', 'ANALYST', 'VIEWER']],
    ['GET', '/findings/prioritized', ['ADMIN', 'ANALYST', 'VIEWER']],
    // operational writes: analyst + admin
    ['POST', '/scans', ['ADMIN', 'ANALYST']],
    ['PATCH', '/findings/abc', ['ADMIN', 'ANALYST']],
    ['POST', '/azure/subscriptions/abc/scan', ['ADMIN', 'ANALYST']],
    ['POST', '/gcp/projects/abc/scan', ['ADMIN', 'ANALYST']],
    ['POST', '/baselines', ['ADMIN', 'ANALYST']],
    ['PATCH', '/baselines/b1/drift/d1', ['ADMIN', 'ANALYST']],
    ['POST', '/approvals/a1/cancel', ['ADMIN', 'ANALYST']],
    ['POST', '/report-schedules/r1/run', ['ADMIN', 'ANALYST']],
    ['POST', '/risk-register', ['ADMIN', 'ANALYST']],
    ['POST', '/compliance/evidence/collect', ['ADMIN', 'ANALYST']],
    // admin only
    ['POST', '/accounts', ['ADMIN']],
    ['POST', '/accounts/setup', ['ADMIN']],
    ['PUT', '/accounts/abc', ['ADMIN']],
    ['DELETE', '/accounts/abc', ['ADMIN']],
    ['GET', '/accounts/abc/credentials', ['ADMIN']],
    ['POST', '/accounts/abc/credentials/verify', ['ADMIN']],
    ['POST', '/azure/subscriptions', ['ADMIN']],
    ['POST', '/gcp/projects/abc/credentials', ['ADMIN']],
    ['DELETE', '/scans/s1', ['ADMIN']],
    ['POST', '/findings/deduplicate', ['ADMIN']],
    ['DELETE', '/azure/scans/findings/cleanup-scanner-errors', ['ADMIN']],
    ['POST', '/integrations', ['ADMIN']],
    ['PUT', '/alerts/a1', ['ADMIN']],
    ['POST', '/alerts/a1/test', ['ADMIN']],
    ['PATCH', '/freeze-windows/f1/toggle', ['ADMIN']],
    ['POST', '/report-schedules', ['ADMIN']],
    ['DELETE', '/report-schedules/r1', ['ADMIN']],
    ['POST', '/approvals/a1/approve', ['ADMIN']],
    ['POST', '/approvals/a1/reject', ['ADMIN']],
    ['DELETE', '/baselines/b1', ['ADMIN']],
    ['POST', '/baselines/b1/drift/d1/revert', ['ADMIN']],
    ['DELETE', '/compliance/evidence/e1', ['ADMIN']],
    ['DELETE', '/anomaly/baselines', ['ADMIN']],
    ['POST', '/anomaly/baselines/seed', ['ADMIN']],
    ['GET', '/audit-logs', ['ADMIN']],
    ['GET', '/audit-logs/x', ['ADMIN']],
  ];

  it.each(cases)('%s %s -> %j', (method, path, roles) => {
    expect(rolesAllowedFor(method, path)).toEqual(roles);
  });

  it('denies unknown or missing roles', () => {
    expect(isAllowed(undefined, 'GET', '/accounts')).toBe(false);
    expect(isAllowed('SUPERUSER', 'GET', '/accounts')).toBe(false);
  });

  it('viewer can never mutate anything', () => {
    for (const m of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      for (const p of ['/accounts', '/findings/x', '/risk-register', '/anything/at/all']) {
        expect(isAllowed('VIEWER', m, p)).toBe(false);
      }
    }
  });

  it('every rule has a description and at least one role', () => {
    for (const r of POLICY_RULES) {
      expect(r.description.length).toBeGreaterThan(0);
      expect(r.roles.length).toBeGreaterThan(0);
    }
  });
});
