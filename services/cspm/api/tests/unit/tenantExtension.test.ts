import { tenantModels, __tenantInternals as t } from '../../src/config/database';
import { runWithTenant, runAsSystem, requireTenantId } from '../../src/config/tenantContext';

const ORG = 'org-123';

describe('tenant extension: model discovery', () => {
  it('tags every domain model and skips identity models', () => {
    for (const m of ['Account', 'Scan', 'Finding', 'AzureSubscription', 'GcpProject', 'AlertConfig', 'RiskItem', 'AuditLog']) {
      expect(tenantModels.has(m)).toBe(true);
    }
    for (const m of ['User', 'Session', 'Tenant', 'TenantMembership']) {
      expect(tenantModels.has(m)).toBe(false);
    }
  });
});

describe('tenant extension: where scoping', () => {
  it('adds orgId to unique lookups', () => {
    expect(t.scopedWhere({ id: 'x' }, ORG, true)).toEqual({ id: 'x', orgId: ORG });
  });
  it('ANDs orgId onto list filters without clobbering user filters', () => {
    expect(t.scopedWhere({ status: 'OPEN', OR: [{ a: 1 }, { b: 2 }] }, ORG, false)).toEqual({
      AND: [{ status: 'OPEN', OR: [{ a: 1 }, { b: 2 }] }, { orgId: ORG }],
    });
  });
  it('handles a missing where', () => {
    expect(t.scopedWhere(undefined, ORG, false)).toEqual({ AND: [{}, { orgId: ORG }] });
  });
});

describe('tenant extension: create stamping', () => {
  it('stamps the root row and nested relation creates', () => {
    const out = t.stampNested(
      'Account',
      {
        name: 'prod',
        credential: { create: { authMethod: 'ACCESS_KEY' } },
        scans: { createMany: { data: [{ status: 'QUEUED' }, { status: 'QUEUED' }] } },
      },
      ORG
    ) as Record<string, any>;
    expect(out.orgId).toBe(ORG);
    expect(out.credential.create.orgId).toBe(ORG);
    expect(out.scans.createMany.data.map((d: any) => d.orgId)).toEqual([ORG, ORG]);
  });

  it('does not override an explicit orgId and leaves non-tenant relations alone', () => {
    const out = t.stampNested(
      'Account',
      { name: 'x', orgId: 'explicit', createdBy: { connect: { id: 'u1' } } },
      ORG
    ) as Record<string, any>;
    expect(out.orgId).toBe('explicit');
    expect(out.createdBy).toEqual({ connect: { id: 'u1' } });
  });

  it('stamps connectOrCreate and nested upsert create branches', () => {
    const out = t.stampNested(
      'Scan',
      {
        summary: { connectOrCreate: { where: { scanId: 's1' }, create: { total: 1 } } },
      },
      ORG
    ) as Record<string, any>;
    expect(out.summary.connectOrCreate.create.orgId).toBe(ORG);
  });
});

describe('tenant extension: system context guard', () => {
  it('requires explicit orgId on creates in system context', () => {
    expect(() => t.assertExplicitOrg('Account', { name: 'x' }, 'create')).toThrow(/orgId explicitly/);
    expect(() => t.assertExplicitOrg('Account', { name: 'x', orgId: ORG }, 'create')).not.toThrow();
    expect(() => t.assertExplicitOrg('Account', [{ orgId: ORG }, { name: 'y' }], 'createMany')).toThrow();
  });
  it('lets nullable-org models (AuditLog) through', () => {
    expect(() => t.assertExplicitOrg('AuditLog', { action: 'x' }, 'create')).not.toThrow();
  });
});

describe('tenant context', () => {
  it('resolves the tenant inside runWithTenant and rejects outside', () => {
    expect(() => requireTenantId()).toThrow(/No tenant context/);
    runWithTenant('abc', () => expect(requireTenantId()).toBe('abc'));
    runAsSystem(() => expect(() => requireTenantId()).toThrow(/System context/));
  });
  it('resolveOrg reports system vs tenant', () => {
    runWithTenant('abc', () => expect(t.resolveOrg('Account')).toEqual({ orgId: 'abc' }));
    runAsSystem(() => expect(t.resolveOrg('Account')).toEqual({ system: true }));
    expect(() => t.resolveOrg('Account')).toThrow(/outside a tenant context/);
  });
});
