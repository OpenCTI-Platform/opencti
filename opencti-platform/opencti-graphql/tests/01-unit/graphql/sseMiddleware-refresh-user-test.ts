import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../src/config/conf');
  return {
    ...actual,
    logApp: { info: vi.fn(), error: vi.fn(), debug: vi.fn(), warn: vi.fn() },
  };
});
vi.mock('../../../src/database/redis');
vi.mock('../../../src/database/stream/stream-handler', () => ({ createStreamProcessor: vi.fn() }));
vi.mock('../../../src/database/engine', () => ({ elCount: vi.fn(), elList: vi.fn(), elFindByIds: vi.fn() }));
vi.mock('../../../src/database/middleware-loader', () => ({ fullRelationsList: vi.fn() }));
vi.mock('../../../src/database/middleware', () => ({ stixLoadById: vi.fn(), storeLoadByIdsWithRefs: vi.fn() }));
vi.mock('../../../src/database/cache', () => ({ getEntitiesListFromCache: vi.fn(), getEntitiesMapFromCache: vi.fn(), getEntityFromCache: vi.fn() }));

import { getEntitiesMapFromCache, getEntityFromCache } from '../../../src/database/cache';
import { SYSTEM_USER } from '../../../src/utils/access';
// eslint-disable-next-line import/extensions
import { refreshStreamUser } from '../../../src/graphql/sseMiddleware.js';

const PLATFORM_ORG = 'platform-org-id';
const OTHER_ORG = 'other-org-id';

const buildUser = (overrides: Record<string, any> = {}) => ({
  id: 'user-id',
  internal_id: 'user-id',
  user_email: 'user@opencti.io',
  capabilities: [{ name: 'TAXIIAPI' }],
  allowed_marking: [{ internal_id: 'marking-a' }],
  organizations: [],
  user_service_account: false,
  ...overrides,
});

const buildRequest = (user: any, contextUser: any = user) => ({
  user,
  userId: user.id,
  capabilities: user.capabilities,
  allowed_marking: user.allowed_marking,
  context: { user: contextUser, user_inside_platform_organization: true } as any,
});

// The user exists in these tests: fail clearly otherwise, and narrow the result type
const refreshExistingStreamUser = async (req: any, channel: any) => {
  const refreshed = await refreshStreamUser(req, channel);
  if (!refreshed) {
    throw new Error('The stream user should still exist');
  }
  return refreshed;
};

describe('refreshStreamUser', () => {
  beforeEach(() => {
    vi.mocked(getEntitiesMapFromCache).mockReset();
    vi.mocked(getEntityFromCache).mockReset();
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_organization: PLATFORM_ORG } as any);
  });

  it('should apply the current rights when a service account is turned into a user', async () => {
    const origin = { socket: 'query', user_id: 'user-id' };
    const serviceAccount = buildUser({ user_service_account: true, organizations: [{ internal_id: OTHER_ORG }], origin });
    const req = buildRequest(serviceAccount);
    const channel = { user: serviceAccount, capabilities: serviceAccount.capabilities, allowed_marking: serviceAccount.allowed_marking } as any;
    // The account is now a regular user, outside the platform organization, with fewer markings
    const updatedUser = buildUser({ user_service_account: false, organizations: [{ internal_id: OTHER_ORG }], allowed_marking: [] });
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map([['user-id', updatedUser]]) as any);

    const { user: refreshed, isRightsChanged } = await refreshExistingStreamUser(req, channel);

    expect(isRightsChanged).toBe(true);
    expect(refreshed.user_service_account).toBe(false);
    expect(refreshed.allowed_marking).toEqual([]);
    // Origin computed at connection is kept
    expect(refreshed.origin).toBe(origin);
    expect(req.user).toBe(refreshed);
    expect(req.allowed_marking).toEqual([]);
    expect(req.context.user).toBe(refreshed);
    expect(req.context.user_inside_platform_organization).toBe(false);
    expect(channel.user).toBe(refreshed);
    expect(channel.allowed_marking).toEqual([]);
  });

  it('should keep a user of the platform organization inside it', async () => {
    const user = buildUser({ organizations: [{ internal_id: PLATFORM_ORG }] });
    const req = buildRequest(user);
    req.context.user_inside_platform_organization = false;
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map([['user-id', { ...user }]]) as any);

    const { isRightsChanged } = await refreshExistingStreamUser(req, undefined);

    expect(req.context.user_inside_platform_organization).toBe(true);
    expect(isRightsChanged).toBe(true);
  });

  it('should not report a rights change when only other attributes changed', async () => {
    const user = buildUser({ organizations: [{ internal_id: PLATFORM_ORG }], groups: [{ internal_id: 'group-a' }, { internal_id: 'group-b' }] });
    const req = buildRequest(user);
    // Same rights, listed in another order, other attributes updated
    const updatedUser = { ...user, name: 'Renamed', groups: [{ internal_id: 'group-b' }, { internal_id: 'group-a' }] };
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map([['user-id', updatedUser]]) as any);

    const { user: refreshed, isRightsChanged } = await refreshExistingStreamUser(req, undefined);

    expect(refreshed.name).toBe('Renamed');
    expect(isRightsChanged).toBe(false);
  });

  it('should report a rights change when a role is removed, even with the same capabilities', async () => {
    const user = buildUser({ organizations: [{ internal_id: PLATFORM_ORG }], roles: [{ internal_id: 'role-a' }, { internal_id: 'role-b' }] });
    const req = buildRequest(user);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map([['user-id', { ...user, roles: [{ internal_id: 'role-a' }] }]]) as any);

    const { isRightsChanged } = await refreshExistingStreamUser(req, undefined);

    expect(isRightsChanged).toBe(true);
  });

  it('should report a rights change when the individual of the user changes', async () => {
    const user = buildUser({ organizations: [{ internal_id: OTHER_ORG }], individual_id: 'individual-a' });
    const req = buildRequest(user);
    req.context.user_inside_platform_organization = false;
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map([['user-id', { ...user, individual_id: 'individual-b' }]]) as any);

    const { isRightsChanged } = await refreshExistingStreamUser(req, undefined);

    expect(isRightsChanged).toBe(true);
  });

  it('should report a rights change when a marking is removed', async () => {
    const user = buildUser({ organizations: [{ internal_id: PLATFORM_ORG }] });
    const req = buildRequest(user);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map([['user-id', { ...user, allowed_marking: [] }]]) as any);

    const { isRightsChanged } = await refreshExistingStreamUser(req, undefined);

    expect(isRightsChanged).toBe(true);
  });

  it('should not replace the requester of a public stream served for another user', async () => {
    const publicUser = buildUser({ id: 'public-user-id', internal_id: 'public-user-id' });
    const requester = buildUser({ id: 'requester-id', internal_id: 'requester-id' });
    const req = buildRequest(publicUser, requester);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map([['public-user-id', { ...publicUser }]]) as any);

    const { user: refreshed } = await refreshExistingStreamUser(req, undefined);

    expect(req.user).toBe(refreshed);
    expect(req.context.user).toBe(requester);
  });

  it('should return undefined when the user no longer exists', async () => {
    const user = buildUser();
    const req = buildRequest(user);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map() as any);

    const refreshed = await refreshStreamUser(req, undefined);

    expect(refreshed).toBeUndefined();
    expect(req.user).toBe(user);
  });

  it('should keep internal users as is', async () => {
    const req = buildRequest(SYSTEM_USER, undefined);

    const refreshed = await refreshStreamUser(req, undefined);

    expect(refreshed).toEqual({ user: SYSTEM_USER, isRightsChanged: false });
    expect(getEntitiesMapFromCache).not.toHaveBeenCalled();
  });
});
