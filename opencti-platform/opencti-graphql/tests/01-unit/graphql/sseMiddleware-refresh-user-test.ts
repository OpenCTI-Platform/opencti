import { beforeEach, describe, expect, it, vi } from 'vitest';

// The maximum lifetime of a session is read from the configuration, which is loaded with the first import
vi.hoisted(() => {
  process.env.APP__SESSION_MAX_LIFETIME = String(12 * 60 * 60 * 1000);
});

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
import { BYPASS, SYSTEM_USER } from '../../../src/utils/access';
// eslint-disable-next-line import/extensions
import { refreshStreamUser } from '../../../src/graphql/sseMiddleware.js';

const PLATFORM_ORG = 'platform-org-id';
const OTHER_ORG = 'other-org-id';

const buildUser = (overrides: Record<string, any> = {}) => ({
  id: 'user-id',
  internal_id: 'user-id',
  user_email: 'user@opencti.io',
  account_status: 'Active',
  capabilities: [{ name: 'TAXIIAPI' }],
  allowed_marking: [{ internal_id: 'marking-a' }],
  organizations: [],
  user_service_account: false,
  ...overrides,
});

const buildRequest = (user: any, contextUser: any = user) => ({
  user,
  userId: user.id,
  context: { user: contextUser, user_inside_platform_organization: true } as any,
});

// Users as the platform users cache gives them: a new object for a user whenever it changes
const mockPlatformUsers = (...users: any[]) => {
  vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map(users.map((u) => [u.id, u])) as any);
};

// The user can still be served in these tests: fail clearly otherwise, and narrow the result type
const refreshServedStreamUser = async (req: any, opts?: { isPublicUser?: boolean }) => {
  const refreshed = await refreshStreamUser(req, opts);
  if (refreshed.error !== undefined || refreshed.user === undefined) {
    throw new Error(`The stream user should still be served: ${refreshed.error}`);
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
    const origin = { socket: 'query', user_id: 'user-id', group_ids: ['group-a'], organization_ids: [OTHER_ORG] };
    const serviceAccount = buildUser({ user_service_account: true, organizations: [{ internal_id: OTHER_ORG }], groups: [{ internal_id: 'group-a' }], origin });
    const req = buildRequest(serviceAccount);
    mockPlatformUsers(buildUser({ user_service_account: true, organizations: [{ internal_id: OTHER_ORG }], groups: [{ internal_id: 'group-a' }] }));
    const { isRightsChanged: isFirstRightsChanged } = await refreshServedStreamUser(req);
    // The account is now a regular user in another group, outside the platform organization, with fewer markings
    const updatedUser = buildUser({ organizations: [{ internal_id: OTHER_ORG }], groups: [{ internal_id: 'group-b' }], allowed_marking: [] });
    mockPlatformUsers(updatedUser);

    const { user: refreshed, isRightsChanged } = await refreshServedStreamUser(req);

    // The first resolution only takes the reference
    expect(isFirstRightsChanged).toBe(false);
    expect(isRightsChanged).toBe(true);
    expect(refreshed.user_service_account).toBe(false);
    expect(refreshed.allowed_marking).toEqual([]);
    // Origin computed at connection is kept, with the current groups and organizations
    expect(refreshed.origin).toEqual({ ...origin, group_ids: ['group-b'], organization_ids: [OTHER_ORG] });
    expect(req.user).toBe(refreshed);
    expect(req.context.user).toBe(refreshed);
    expect(req.context.user_inside_platform_organization).toBe(false);
  });

  it('should report a rights change when the platform organization changes, with the same user', async () => {
    const user = buildUser({ organizations: [{ internal_id: OTHER_ORG }] });
    const req = buildRequest(user);
    mockPlatformUsers(user);
    await refreshServedStreamUser(req);
    expect(req.context.user_inside_platform_organization).toBe(false);
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_organization: OTHER_ORG } as any);

    const { isRightsChanged } = await refreshServedStreamUser(req);

    expect(req.context.user_inside_platform_organization).toBe(true);
    expect(isRightsChanged).toBe(true);
  });

  it('should report a rights change whenever the users cache gives a new object for the user', async () => {
    const user = buildUser({ organizations: [{ internal_id: PLATFORM_ORG }] });
    const req = buildRequest(user);
    mockPlatformUsers(user);
    await refreshServedStreamUser(req);
    // Same users cache entry: nothing changed
    const { isRightsChanged: isUnchanged } = await refreshServedStreamUser(req);
    mockPlatformUsers({ ...user });

    const { isRightsChanged } = await refreshServedStreamUser(req);

    expect(isUnchanged).toBe(false);
    expect(isRightsChanged).toBe(true);
  });

  it('should not serve a user whose account is locked', async () => {
    const user = buildUser();
    const req = buildRequest(user);
    mockPlatformUsers({ ...user, account_status: 'Locked' });

    const refreshed = await refreshStreamUser(req);

    expect(refreshed.error).toBeDefined();
    expect(req.user).toBe(user);
  });

  it('should not serve a user whose account expired', async () => {
    const user = buildUser();
    const req = buildRequest(user);
    // The expiration manager only sets the Expired status later
    mockPlatformUsers({ ...user, account_lock_after_date: '2020-01-01T00:00:00.000Z' });

    const refreshed = await refreshStreamUser(req);

    expect(refreshed.error).toBeDefined();
  });

  it('should not check the account status of the user of a public stream', async () => {
    const publicUser = buildUser({ id: 'public-user-id', internal_id: 'public-user-id' });
    const req = buildRequest(publicUser, undefined);
    mockPlatformUsers({ ...publicUser, account_status: 'Locked' });

    const { user: refreshed } = await refreshServedStreamUser(req, { isPublicUser: true });

    expect(refreshed.id).toBe('public-user-id');
  });

  describe('with a stream opened with a session', () => {
    const TWELVE_HOURS = 12 * 60 * 60 * 1000;
    const withSession = (req: any, loginTime: number) => ({
      ...req,
      session: { user: { id: req.user.id, session_creation: new Date(loginTime).toISOString() } },
    });

    it('should serve the user while the session is under its maximum lifetime', async () => {
      const user = buildUser();
      const req = withSession(buildRequest(user), Date.now() - TWELVE_HOURS + 60 * 1000);
      mockPlatformUsers(user);

      const { user: refreshed } = await refreshServedStreamUser(req);

      expect(refreshed.id).toBe('user-id');
    });

    it('should not serve the user once the session reached its maximum lifetime', async () => {
      const user = buildUser();
      const req = withSession(buildRequest(user), Date.now() - TWELVE_HOURS - 60 * 1000);
      mockPlatformUsers(user);

      const refreshed = await refreshStreamUser(req);

      expect(refreshed.error).toBe('the session of the user reached its maximum lifetime');
    });

    it('should not check the session of the requester of a public stream', async () => {
      const publicUser = buildUser({ id: 'public-user-id', internal_id: 'public-user-id' });
      const req = withSession(buildRequest(publicUser, undefined), Date.now() - TWELVE_HOURS - 60 * 1000);
      mockPlatformUsers(publicUser);

      const { user: refreshed } = await refreshServedStreamUser(req, { isPublicUser: true });

      expect(refreshed.id).toBe('public-user-id');
    });
  });

  describe('with an applicant impersonated by the authenticated user', () => {
    const applicant = buildUser({ origin: { user_id: 'user-id', real_authentication_id: 'worker-id' } });
    const worker = buildUser({ id: 'worker-id', internal_id: 'worker-id', capabilities: [{ name: BYPASS }] });

    it('should serve the applicant while the authenticated user can impersonate it', async () => {
      const req = buildRequest(applicant);
      mockPlatformUsers(buildUser(), worker);

      const { user: refreshed } = await refreshServedStreamUser(req);

      expect(refreshed.id).toBe('user-id');
      expect(refreshed.origin.real_authentication_id).toBe('worker-id');
    });

    it('should not serve the applicant once the authenticated user lost the bypass capability', async () => {
      const req = buildRequest(applicant);
      mockPlatformUsers(buildUser(), { ...worker, capabilities: [{ name: 'TAXIIAPI' }] });

      const refreshed = await refreshStreamUser(req);

      expect(refreshed.error).toBeDefined();
      expect(req.user).toBe(applicant);
    });

    it('should not serve the applicant once the authenticated user is locked', async () => {
      const req = buildRequest(applicant);
      mockPlatformUsers(buildUser(), { ...worker, account_status: 'Locked' });

      const refreshed = await refreshStreamUser(req);

      expect(refreshed.error).toBeDefined();
    });

    it('should not serve the applicant once the authenticated user no longer exists', async () => {
      const req = buildRequest(applicant);
      mockPlatformUsers(buildUser());

      const refreshed = await refreshStreamUser(req);

      expect(refreshed.error).toBeDefined();
    });
  });

  it('should not replace the requester of a public stream served for another user', async () => {
    const publicUser = buildUser({ id: 'public-user-id', internal_id: 'public-user-id' });
    const requester = buildUser({ id: 'requester-id', internal_id: 'requester-id' });
    const req = buildRequest(publicUser, requester);
    mockPlatformUsers({ ...publicUser });

    const { user: refreshed } = await refreshServedStreamUser(req, { isPublicUser: true });

    expect(req.user).toBe(refreshed);
    expect(req.context.user).toBe(requester);
  });

  it('should not serve a user who no longer exists', async () => {
    const user = buildUser();
    const req = buildRequest(user);
    mockPlatformUsers();

    const refreshed = await refreshStreamUser(req);

    expect(refreshed.error).toBeDefined();
    expect(req.user).toBe(user);
  });

  it('should keep internal users as is', async () => {
    const req = buildRequest(SYSTEM_USER, undefined);

    const refreshed = await refreshStreamUser(req);

    expect(refreshed).toEqual({ user: SYSTEM_USER, isRightsChanged: false });
    expect(getEntitiesMapFromCache).not.toHaveBeenCalled();
  });
});
