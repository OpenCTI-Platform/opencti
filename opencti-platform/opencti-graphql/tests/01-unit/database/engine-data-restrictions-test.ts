import { beforeEach, describe, expect, it, vi } from 'vitest';
import { buildDataRestrictions } from '../../../src/database/engine';
import { getEntitiesListFromCache, getEntityFromCache } from '../../../src/database/cache';
import { BYPASS } from '../../../src/utils/access';
import type { AuthContext, AuthUser } from '../../../src/types/user';

vi.mock('../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/cache')>()),
  getEntitiesListFromCache: vi.fn(),
  getEntityFromCache: vi.fn(),
}));

const testContext = {} as AuthContext;
const MARKING_ALLOWED = 'a1f7c0de-0000-4000-8000-000000000001';
const MARKING_FORBIDDEN = 'a1f7c0de-0000-4000-8000-000000000002';
const MARKING_SEARCH_KEY = 'rel_object-marking.internal_id.keyword';

const buildUser = (opts: { bypass: boolean; serviceAccount: boolean; allowedMarkings?: string[] }) => ({
  id: 'b6f4ee64-1d9c-4b7c-9a5e-3c2b1a0f9e8d',
  internal_id: 'b6f4ee64-1d9c-4b7c-9a5e-3c2b1a0f9e8d',
  capabilities: [{ name: opts.bypass ? BYPASS : 'KNOWLEDGE' }],
  allowed_marking: (opts.allowedMarkings ?? []).map((internal_id) => ({ internal_id })),
  groups: [],
  organizations: [],
  roles: [],
  user_service_account: opts.serviceAccount,
}) as unknown as AuthUser;

beforeEach(() => {
  vi.mocked(getEntitiesListFromCache).mockResolvedValue([{ internal_id: MARKING_ALLOWED }, { internal_id: MARKING_FORBIDDEN }] as any);
  vi.mocked(getEntityFromCache).mockResolvedValue({ platform_organization: undefined } as any);
});

describe('buildDataRestrictions authorized members filter', () => {
  it('should not send the authorized members filter for a service account with bypass', async () => {
    const restrictions = await buildDataRestrictions(testContext, buildUser({ bypass: true, serviceAccount: true }));
    expect(restrictions).toEqual({ must: [], must_not: [] });
  });
  it('should keep the authorized members filter for a user with bypass that is not a service account', async () => {
    const restrictions = await buildDataRestrictions(testContext, buildUser({ bypass: true, serviceAccount: false }));
    expect(restrictions.must).toHaveLength(1);
    expect(JSON.stringify(restrictions.must[0])).toContain('restricted_members');
    expect(restrictions.must_not).toEqual([]);
  });
  it('should not send the authorized members filter for a service account without bypass', async () => {
    const user = buildUser({ bypass: false, serviceAccount: true, allowedMarkings: [MARKING_ALLOWED, MARKING_FORBIDDEN] });
    const restrictions = await buildDataRestrictions(testContext, user);
    expect(restrictions).toEqual({ must: [], must_not: [] });
  });
  it('should keep the authorized members access of a service account in the organization restriction', async () => {
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_organization: 'c0ffee00-0000-4000-8000-000000000001' } as any);
    const context = { user_inside_platform_organization: false } as AuthContext;
    const user = buildUser({ bypass: false, serviceAccount: true, allowedMarkings: [MARKING_ALLOWED, MARKING_FORBIDDEN] });
    const restrictions = await buildDataRestrictions(context, user);
    expect(restrictions.must).toHaveLength(1);
    const organizationShould = restrictions.must[0].bool.should;
    expect(organizationShould.some((clause: any) => JSON.stringify(clause).includes('"path":"restricted_members"'))).toBe(true);
  });
});

describe('buildDataRestrictions marking restriction', () => {
  it('should exclude the markings the user cannot access in must_not', async () => {
    const user = buildUser({ bypass: false, serviceAccount: false, allowedMarkings: [MARKING_ALLOWED] });
    const restrictions = await buildDataRestrictions(testContext, user);
    expect(restrictions.must_not).toEqual([{ terms: { [MARKING_SEARCH_KEY]: [MARKING_FORBIDDEN] } }]);
    expect(JSON.stringify(restrictions.must)).not.toContain(MARKING_SEARCH_KEY);
  });
  it('should not exclude anything when the user can access every marking', async () => {
    const user = buildUser({ bypass: false, serviceAccount: false, allowedMarkings: [MARKING_ALLOWED, MARKING_FORBIDDEN] });
    const restrictions = await buildDataRestrictions(testContext, user);
    expect(restrictions.must_not).toEqual([]);
    expect(JSON.stringify(restrictions.must)).not.toContain(MARKING_SEARCH_KEY);
  });
  it('should exclude every marked data when the user has no marking', async () => {
    const user = buildUser({ bypass: false, serviceAccount: false, allowedMarkings: [] });
    const restrictions = await buildDataRestrictions(testContext, user);
    expect(restrictions.must_not).toEqual([{ exists: { field: 'rel_object-marking.internal_id' } }]);
  });
});
