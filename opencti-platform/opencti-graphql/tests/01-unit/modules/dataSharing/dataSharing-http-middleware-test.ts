import { describe, expect, it, vi, beforeEach } from 'vitest';

// Mock all external dependencies before importing the modules under test
vi.mock('../../../../src/http/httpAuthenticatedContext', () => ({
  createAuthenticatedContext: vi.fn(),
}));
vi.mock('../../../../src/database/cache', () => ({
  getEntitiesListFromCache: vi.fn(),
  getEntityFromCache: vi.fn(),
}));
vi.mock('../../../../src/domain/feed', () => ({
  findById: vi.fn(),
}));
vi.mock('../../../../src/http/httpServer-draft', () => ({
  checkDraftInContext: vi.fn(),
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
import { getEntitiesListFromCache } from '../../../../src/database/cache';
// eslint-disable-next-line import/extensions
import { authenticate, authenticateForPublic } from '../../../../src/graphql/sseMiddleware.js';
// eslint-disable-next-line import/extensions
import { checkAuthenticationFromRequest } from '../../../../src/http/httpTaxii.js';
import initHttpRollingFeeds from '../../../../src/http/httpRollingFeed';
import { findById as findFeedById } from '../../../../src/domain/feed';
import { checkDraftInContext } from '../../../../src/http/httpServer-draft';
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
    setHeader: vi.fn(),
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

// ─── draft-context authorization regression (security fix, non-GraphQL routes) ──
// These routes read `context.draft_context` (set from the `opencti-draft-id`
// header) to overlay draft-scoped data, but historically only the GraphQL
// context enforced draft membership via `checkDraftInContext`. Each route
// below must call it and must abort — without touching feed/collection/stream
// data — the moment it rejects.

describe('checkAuthenticationFromRequest (TAXII) draft authorization', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('rejects when the caller is not authorized for the requested draft', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({
      user: { id: 'user-b', capabilities: [] },
      draft_context: 'restricted-draft',
    } as any);
    vi.mocked(checkDraftInContext).mockRejectedValue(new Error('Draft restricted-draft cannot be found'));

    const req = makeMockReq();
    const res = makeMockRes();

    await expect(checkAuthenticationFromRequest(req, res)).rejects.toThrow('Draft restricted-draft cannot be found');
    expect(checkDraftInContext).toHaveBeenCalled();
  });

  it('returns the context when the draft check passes', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({
      user: { id: 'user-a', capabilities: [] },
      draft_context: 'own-draft',
    } as any);
    vi.mocked(checkDraftInContext).mockResolvedValue(undefined);

    const req = makeMockReq();
    const res = makeMockRes();

    const context = await checkAuthenticationFromRequest(req, res);

    expect(context.user?.id).toBe('user-a');
  });
});

describe('rolling feed route (httpRollingFeed) draft authorization', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const captureFeedHandler = () => {
    let handler: any;
    const fakeApp = { get: (_path: string, h: any) => {
      handler = h;
    } };
    initHttpRollingFeeds(fakeApp as any);
    return handler;
  };

  it('does not stream feed content when the caller cannot access the requested draft', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({
      user: { id: 'user-b', capabilities: [] },
      draft_context: 'restricted-draft',
    } as any);
    vi.mocked(findFeedById).mockResolvedValue({
      feed_public: true,
      feed_types: [],
      feed_attributes: [],
      separator: ',',
      include_header: false,
      rolling_time: 5,
    } as any);
    vi.mocked(checkDraftInContext).mockRejectedValue(new Error('Draft restricted-draft cannot be found'));

    const handler = captureFeedHandler();
    const req = { params: { id: 'feed-1' }, headers: {} };
    const res = { set: vi.fn(), setHeader: vi.fn(), status: vi.fn().mockReturnThis(), send: vi.fn(), write: vi.fn() };

    await handler(req, res);

    expect(checkDraftInContext).toHaveBeenCalled();
    expect(res.write).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(500);
  });
});

describe('authenticate / authenticateForPublic (SSE) draft authorization', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('authenticate: does not call next() when the caller cannot access the requested draft', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({
      user: { id: 'user-b', capabilities: [] },
      draft_context: 'restricted-draft',
    } as any);
    vi.mocked(checkDraftInContext).mockRejectedValue(new Error('Draft restricted-draft cannot be found'));

    const req = makeMockReq();
    const res = makeMockRes();
    const next = vi.fn();

    await authenticate(req, res, next);

    expect(checkDraftInContext).toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(500);
  });

  it('authenticateForPublic: does not open the stream when the caller cannot access the requested draft', async () => {
    vi.mocked(createAuthenticatedContext).mockResolvedValue({
      user: { id: 'user-b', capabilities: [] },
      draft_context: 'restricted-draft',
    } as any);
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([
      { ...MOCK_STREAM_COLLECTION, stream_public: false, restricted_members: [] },
    ] as any);
    vi.mocked(checkDraftInContext).mockRejectedValue(new Error('Draft restricted-draft cannot be found'));

    const req = makeMockReq({ id: 'stream-1' });
    const res = makeMockRes();
    const next = vi.fn();

    await authenticateForPublic(req, res, next);

    expect(checkDraftInContext).toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(500);
  });
});
