jest.mock('../../src/config/database', () => ({ prisma: { auditLog: { create: jest.fn() } } }));
jest.mock('../../src/config/logger', () => ({ logger: { warn: jest.fn(), debug: jest.fn() } }));

import { redact, deriveAction } from '../../src/middleware/auditLog';

describe('audit redact', () => {
  it('masks secret-looking keys at any depth and keeps the rest', () => {
    const out = redact({
      name: 'prod',
      password: 'p@ss',
      nested: { accessKeyId: 'AKIA', secretAccessKey: 'xyz', region: 'us-east-1' },
      list: [{ token: 't' }, { ok: 1 }],
    }) as Record<string, unknown>;
    const nested = out.nested as Record<string, unknown>;
    const list = out.list as Array<Record<string, unknown>>;
    expect(out.name).toBe('prod');
    expect(out.password).toBe('[REDACTED]');
    expect(nested.accessKeyId).toBe('[REDACTED]');
    expect(nested.secretAccessKey).toBe('[REDACTED]');
    expect(nested.region).toBe('us-east-1');
    expect(list[0].token).toBe('[REDACTED]');
    expect(list[1].ok).toBe(1);
  });

  it('passes primitives through', () => {
    expect(redact('x')).toBe('x');
    expect(redact(3)).toBe(3);
    expect(redact(null)).toBe(null);
  });
});

describe('audit deriveAction', () => {
  it.each([
    ['POST', '/accounts', 'accounts.create'],
    ['PUT', '/accounts/abc', 'accounts.update'],
    ['DELETE', '/accounts/abc', 'accounts.delete'],
    ['POST', '/auth/login', 'auth.login'],
    ['POST', '/approvals/a1/approve', 'approvals.approve'],
    ['POST', '/azure/subscriptions/s1/scan', 'azure.scan'],
    ['POST', '/report-schedules/r1/run', 'report_schedules.run'],
    ['PATCH', '/findings/f1', 'findings.update'],
    ['POST', '/baselines/b1/drift/d1/revert', 'baselines.revert'],
  ])('%s %s -> %s', (m, p, expected) => {
    expect(deriveAction(m, p)).toBe(expected);
  });
});
