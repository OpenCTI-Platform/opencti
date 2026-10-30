import { describe, expect, it, vi, beforeEach } from 'vitest';

// Mock all external dependencies before importing the modules under test
vi.mock('../../../../src/http/httpAuthenticatedContext', () => ({
  createAuthenticatedContext: vi.fn(),
}));
vi.mock('../../../../src/database/cache', () => ({
  getEntitiesListFromCache: vi.fn(),
  getEntityFromCache: vi.fn(),
}));
vi.mock('../../../../src/modules/dataSharing/dataSharing-utils', () => ({
  resolvePublicUser: vi.fn(),
  validatePublicUserId: vi.fn(),
}));
vi.mock('../../../../src/modules/dataSharing/taxiiCollection-domain', () => ({
  findById: vi.fn(),
}));
vi.mock('../../../../src/utils/access', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/utils/access')>();
  return {
    ...actual,
    executionContext: vi.fn(() => ({ user: null, user_inside_platform_organization: false })),
    isUserHasCapability: vi.fn(() => true),
    isUserInPlatformOrganization: vi.fn(() => false),
  };
});
vi.mock('../../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../../src/config/conf');
  return {
    ...actual,
    logApp: { info: vi.fn(), error: vi.fn(), debug: vi.fn(), warn: vi.fn() },
  };
});
// Prevent module-level DB connections
vi.mock('../../../../src/database/redis');
vi.mock('../../../../src/database/stream/stream-handler', () => ({ createStreamProcessor: vi.fn() }));
vi.mock('../../../../src/database/engine', () => ({ elCount: vi.fn(), elList: vi.fn(), elFindByIds: vi.fn() }));
vi.mock('../../../../src/database/middleware-loader', () => ({ fullRelationsList: vi.fn(), fullEntitiesList: vi.fn() }));
vi.mock('../../../../src/database/middleware', () => ({ stixLoadById: vi.fn(), storeLoadByIdsWithRefs: vi.fn(), fullEntitiesOrRelationsList: vi.fn() }));
vi.mock('../../../../src/schema/identifier', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/schema/identifier')>();
  return { ...actual, generateInternalId: vi.fn(() => 'mock-id') };
});

import { createAuthenticatedContext } from '../../../../src/http/httpAuthenticatedContext';
import { getEntitiesListFromCache, getEntityFromCache } from '../../../../src/database/cache';
import { resolvePublicUser } from '../../../../src/modules/dataSharing/dataSharing-utils';
import { findById as findTaxiiCollection } from '../../../../src/modules/dataSharing/taxiiCollection-domain';
// eslint-disable-next-line import/extensions
import { authenticate, authenticateForPublic, sendEventWithFilteredObjectRefs } from '../../../../src/graphql/sseMiddleware.js';
import { elFindByIds } from '../../../../src/database/engine';
// eslint-disable-next-line import/extensions
import { extractUserAndCollection } from '../../../../src/http/httpTaxii.js';
import { resolveUserForFeed } from '../../../../src/http/httpRollingFeed.js';
import { emptyFilterGroup } from '../../../../src/utils/filtering/filtering-utils';

// ─── helpers ─────────────────────────────────────────────────────────────────

const makeMockReq = (params: Record<string, string> = {}, headers: Record<string, string> = {}) => ({
  params,
  headers,
  query: {},
  context: undefined as any,
  expirationTime: undefined as any,
  user: undefined as any,
  userId: undefined as any,
  capabilities: undefined as any,
  allowed_marking: undefined as any,
  collection: undefined as any,
  streamFilters: undefined as any,
  on: vi.fn(),
});

const makeMockRes = () => {
  const res: any = {
    statusMessage: '',
    status: vi.fn().mockReturnThis(),
    end: vi.fn().mockReturnThis(),
    send: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };
  return res;
};

const MOCK_STREAM_COLLECTION = {
  id: 'stream-1',
  stream_public: true,
  stream_public_user_id: 'public-user-id',
  stream_live: true,
  filters: JSON.stringify(emptyFilterGroup),
  restricted_members: [],
};

const MOCK_TAXII_COLLECTION = {
  id: 'taxii-1',
  taxii_public: true,
  taxii_public_user_id: 'public-user-id',
};

const MOCK_PUBLIC_USER = {
  id: 'public-user-id',
  user_email: 'public@test.com',
  capabilities: [],
  allowed_marking: [],
};

// ─── authenticateForPublic (sseMiddleware) ───────────────────────────────────

describe('authenticateForPublic middleware', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls next() and sets req.user for a public stream with no auth user', async () => {
    const mockContext: any = { user: null, user_inside_platform_organization: false };
    vi.mocked(createAuthenticatedContext).mockResolvedValue(mockContext);
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([MOCK_STREAM_COLLECTION] as any);
    vi.mocked(resolvePublicUser).mockResolvedValue(MOCK_PUBLIC_USER as any);
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_organization: null } as any);

    const req = makeMockReq({ id: 'stream-1' });
    const res = makeMockRes();
    const next = vi.fn();

    await authenticateForPublic(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.user).toBe(MOCK_PUBLIC_USER);
    expect(req.userId).toBe('public-user-id');
    expect(res.status).not.toHaveBeenCalled();
  });

  it('recomputes user_inside_platform_organization for the resolved public user even when an admin is authenticated', async () => {
    // Simulates an admin (bypass, inside platform org) accessing a public stream URL.
    // user_inside_platform_organization must be overridden to reflect the *public user*, not the admin.
    const adminUser = { id: 'admin-id', user_email: 'admin@test.com', capabilities: [], allowed_marking: [], organizations: [] };
    const mockContext: any = { user: adminUser, user_inside_platform_organization: true };
    vi.mocked(createAuthenticatedContext).mockResolvedValue(mockContext);
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([MOCK_STREAM_COLLECTION] as any);
    vi.mocked(resolvePublicUser).mockResolvedValue({ ...MOCK_PUBLIC_USER, organizations: [{ internal_id: 'filigran-org' }] } as any);
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_organization: 'bae-org-id' } as any);
    // isUserInPlatformOrganization returns false: public user (Filigran) is NOT in the platform org (BAE)
    const { isUserInPlatformOrganization } = await import('../../../../src/utils/access');
    vi.mocked(isUserInPlatformOrganization).mockReturnValue(false);

    const req = makeMockReq({ id: 'stream-1' });
    const res = makeMockRes();
    const next = vi.fn();

    await authenticateForPublic(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.user).not.toBe(adminUser);
    // Context must now reflect the public user's org membership, NOT the admin's
    expect(mockContext.user_inside_platform_organization).toBe(false);
  });

  it('returns 401 when stream does not exist and user is unauthenticated', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([] as any);

    const req = makeMockReq({ id: 'nonexistent-stream' });
    const res = makeMockRes();
    const next = vi.fn();

    await authenticateForPublic(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('returns 401 when stream is not public and user is unauthenticated', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([
      { ...MOCK_STREAM_COLLECTION, stream_public: false },
    ] as any);

    const req = makeMockReq({ id: 'stream-1' });
    const res = makeMockRes();
    const next = vi.fn();

    await authenticateForPublic(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('returns 500 when resolvePublicUser throws', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([MOCK_STREAM_COLLECTION] as any);
    vi.mocked(resolvePublicUser).mockRejectedValue(new Error('Public user not found'));

    const req = makeMockReq({ id: 'stream-1' });
    const res = makeMockRes();
    const next = vi.fn();

    await authenticateForPublic(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.statusMessage).toContain('Public user not found');
  });

  it('calls next() with authenticated user on a private stream', async () => {
    const mockAuthUser = { id: 'auth-user', user_email: 'auth@test.com', capabilities: [], allowed_marking: [] };
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: mockAuthUser } as any);
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([
      { ...MOCK_STREAM_COLLECTION, stream_public: false, restricted_members: [] },
    ] as any);
    // isUserHasCapability returns true by default from mock

    const req = makeMockReq({ id: 'stream-1' });
    const res = makeMockRes();
    const next = vi.fn();

    await authenticateForPublic(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.user).toBe(mockAuthUser);
  });
});

// ─── sendEventWithFilteredObjectRefs (object_refs redaction) ─────────────────

describe('sendEventWithFilteredObjectRefs', () => {
  const CACHED_REF = 'malware--cached';
  const ACCESSIBLE_UNCACHED_REF = 'malware--accessible';
  const RESTRICTED_UNCACHED_REF = 'malware--restricted';

  const makeEvent = (objectRefs?: string[]) => ({
    eventId: 'event-1',
    eventType: 'update',
    eventData: { data: { id: 'report--x', ...(objectRefs ? { object_refs: objectRefs } : {}) } },
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // Refs accessible to the user but missing from the cache (e.g. evicted) must be recovered
  // through the access-controlled elFindByIds and kept in object_refs.
  it('keeps accessible refs that are not in cache by resolving them through elFindByIds', async () => {
    const cache = new Map([[CACHED_REF, 'hit']]);
    const client = { sendEvent: vi.fn() };
    // The access-controlled lookup returns only the accessible ref, not the restricted one
    vi.mocked(elFindByIds).mockResolvedValue({ [ACCESSIBLE_UNCACHED_REF]: { standard_id: ACCESSIBLE_UNCACHED_REF } } as any);

    const event = makeEvent([CACHED_REF, ACCESSIBLE_UNCACHED_REF, RESTRICTED_UNCACHED_REF]);
    await sendEventWithFilteredObjectRefs({} as any, {} as any, cache as any, client as any, event as any);

    // Only the uncached refs are looked up, with the all-ids map option
    expect(elFindByIds).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      [ACCESSIBLE_UNCACHED_REF, RESTRICTED_UNCACHED_REF],
      expect.objectContaining({ toMap: true, mapWithAllIds: true }),
    );
    // Cached + accessible-uncached kept, restricted dropped
    expect(event.eventData.data.object_refs).toEqual([CACHED_REF, ACCESSIBLE_UNCACHED_REF]);
    expect(client.sendEvent).toHaveBeenCalledWith('event-1', 'update', event.eventData);
  });

  it('does not query elFindByIds when every ref is already in cache', async () => {
    const cache = new Map([[CACHED_REF, 'hit'], [ACCESSIBLE_UNCACHED_REF, 'hit']]);
    const client = { sendEvent: vi.fn() };

    const event = makeEvent([CACHED_REF, ACCESSIBLE_UNCACHED_REF]);
    await sendEventWithFilteredObjectRefs({} as any, {} as any, cache as any, client as any, event as any);

    expect(elFindByIds).not.toHaveBeenCalled();
    expect(event.eventData.data.object_refs).toEqual([CACHED_REF, ACCESSIBLE_UNCACHED_REF]);
    expect(client.sendEvent).toHaveBeenCalledWith('event-1', 'update', event.eventData);
  });

  it('sends the event untouched when there is no object_refs', async () => {
    const cache = new Map();
    const client = { sendEvent: vi.fn() };

    const event = makeEvent();
    await sendEventWithFilteredObjectRefs({} as any, {} as any, cache as any, client as any, event as any);

    expect(elFindByIds).not.toHaveBeenCalled();
    expect(client.sendEvent).toHaveBeenCalledWith('event-1', 'update', event.eventData);
  });
});

// ─── authenticate (sseMiddleware, private stream token auth) ─────────────────

describe('authenticate middleware (OTP enforcement)', () => {
  const AUTH_USER = { id: 'auth-user', user_email: 'auth@test.com', capabilities: [{ name: 'KNOWLEDGE' }], allowed_marking: [] };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns 401 when otp_mandatory is true and user_otp_validated is false (OTP already activated)', async () => {
    // Regression: a stream must not be accessible when the platform enforces OTP
    // and the session has not validated it -> checkOTPValidationStatus => VALIDATION_REQUIRED
    vi.mocked(createAuthenticatedContext).mockResolvedValue({
      user: { ...AUTH_USER, otp_activated: true },
      otp_mandatory: true,
      user_otp_validated: false,
    } as any);

    const req = makeMockReq();
    const res = makeMockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.statusMessage).toContain('validate your two-factor authentication');
    expect(req.user).toBeUndefined();
  });

  it('returns 401 when otp_mandatory is true, user_otp_validated is false and OTP is not yet activated', async () => {
    // checkOTPValidationStatus => ACTIVATION_REQUIRED
    vi.mocked(createAuthenticatedContext).mockResolvedValue({
      user: { ...AUTH_USER, otp_activated: false },
      otp_mandatory: true,
      user_otp_validated: false,
    } as any);

    const req = makeMockReq();
    const res = makeMockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.statusMessage).toContain('activate your two-factor authentication');
  });

  it('calls next() and populates req when OTP is validated', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({
      user: { ...AUTH_USER, otp_activated: true },
      otp_mandatory: true,
      user_otp_validated: true,
    } as any);

    const req = makeMockReq();
    const res = makeMockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
    expect(req.user).toEqual({ ...AUTH_USER, otp_activated: true });
    expect(req.userId).toBe('auth-user');
    expect(req.capabilities).toEqual(AUTH_USER.capabilities);
  });

  it('calls next() when otp_mandatory is false and user has not self-activated OTP', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({
      user: { ...AUTH_USER, otp_activated: false },
      otp_mandatory: false,
      user_otp_validated: false,
    } as any);

    const req = makeMockReq();
    const res = makeMockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('returns 401 when no user is resolved from the context', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({ user: null } as any);

    const req = makeMockReq();
    const res = makeMockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.statusMessage).toContain('not authenticated');
  });

  it('returns 500 when context resolution throws', async () => {
    vi.mocked(createAuthenticatedContext).mockRejectedValue(new Error('boom'));

    const req = makeMockReq();
    const res = makeMockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.statusMessage).toContain('boom');
  });
});

// ─── extractUserAndCollection (httpTaxii) ────────────────────────────────────

describe('extractUserAndCollection middleware helper (TAXII)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns context, public user and collection for a public taxii collection', async () => {
    vi.mocked(findTaxiiCollection).mockResolvedValue(MOCK_TAXII_COLLECTION as any);
    vi.mocked(resolvePublicUser).mockResolvedValue(MOCK_PUBLIC_USER as any);
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_organization: null } as any);

    const req = makeMockReq();
    const res = makeMockRes();

    const result = await extractUserAndCollection(req, res, 'taxii-1');

    expect(result.context).toBeDefined();
    expect(result.user).toBe(MOCK_PUBLIC_USER);
    expect(result.collection).toBe(MOCK_TAXII_COLLECTION);
  });

  it('throws ForbiddenAccess when collection not found', async () => {
    vi.mocked(findTaxiiCollection).mockResolvedValue(null as any);

    const req = makeMockReq();
    const res = makeMockRes();

    await expect(extractUserAndCollection(req, res, 'nonexistent')).rejects.toThrow();
  });
});

// ─── resolveUserForFeed (httpRollingFeed) ────────────────────────────────────

describe('resolveUserForFeed helper', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns authenticated user when context.user is set and feed is private', async () => {
    const mockUser = { id: 'auth-user', user_email: 'auth@test.com' } as any;
    const context = { user: mockUser } as any;
    const feed = { feed_public: false, feed_public_user_id: undefined } as any;

    const result = await resolveUserForFeed(context, feed);

    expect(result).toBe(mockUser);
    expect(resolvePublicUser).not.toHaveBeenCalled();
  });

  it('calls resolvePublicUser for a public feed even when an authenticated user is in context (admin session)', async () => {
    // Admin is authenticated but the feed is public — the public user must always win.
    const adminUser = { id: 'admin-id', user_email: 'admin@test.com' } as any;
    vi.mocked(resolvePublicUser).mockResolvedValue({ id: 'public-user' } as any);
    const context = { user: adminUser } as any;
    const feed = { feed_public: true, feed_public_user_id: 'public-id' } as any;

    const result = await resolveUserForFeed(context, feed);

    expect(resolvePublicUser).toHaveBeenCalledWith(context, 'public-id');
    expect(result).toEqual({ id: 'public-user' });
    expect(result).not.toBe(adminUser);
  });

  it('calls resolvePublicUser when context.user is null (public feed, no session)', async () => {
    vi.mocked(resolvePublicUser).mockResolvedValue({ id: 'public-user' } as any);
    const context = { user: null } as any;
    const feed = { feed_public: true, feed_public_user_id: 'public-id' } as any;

    const result = await resolveUserForFeed(context, feed);

    expect(resolvePublicUser).toHaveBeenCalledWith(context, 'public-id');
    expect(result).toEqual({ id: 'public-user' });
  });
});
