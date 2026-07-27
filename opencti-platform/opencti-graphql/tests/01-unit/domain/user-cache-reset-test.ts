import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockElRawUpdateByQuery = vi.fn().mockResolvedValue({ updated: 1 });
const mockPublishCacheResetEvent = vi.fn().mockResolvedValue(undefined);

vi.mock('../../../src/database/engine', () => ({
  elRawUpdateByQuery: (...args: unknown[]) => mockElRawUpdateByQuery(...args),
  elLoadBy: vi.fn(),
}));

vi.mock('../../../src/database/redis', () => ({
  delEditContext: vi.fn(),
  notify: vi.fn(),
  publishCacheResetEvent: (...args: unknown[]) => mockPublishCacheResetEvent(...args),
  setEditContext: vi.fn(),
}));

vi.mock('../../../src/database/utils', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return { ...actual };
});

vi.mock('../../../src/database/cache', () => ({
  getEntitiesListFromCache: vi.fn(async () => []),
  getEntitiesMapFromCache: vi.fn(async () => new Map()),
  getEntityFromCache: vi.fn(async () => ({})),
}));

vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  createRelation: vi.fn(),
  deleteElementById: vi.fn(),
  deleteRelationsByFromAndTo: vi.fn(),
  patchAttribute: vi.fn(),
  updateAttribute: vi.fn(),
  updatedInputsToData: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(async () => []),
  fullEntitiesThoughAggregationConnection: vi.fn(),
  fullEntitiesThroughRelationsToList: vi.fn(async () => []),
  fullRelationsList: vi.fn(async () => []),
  internalFindByIds: vi.fn(async () => []),
  internalLoadById: vi.fn(),
  pageEntitiesConnection: vi.fn(),
  pageRegardingEntitiesConnection: vi.fn(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../src/database/session', () => ({
  findUserSessions: vi.fn(async () => []),
  killSessions: vi.fn(),
  killUserSessions: vi.fn(),
}));

vi.mock('../../../src/database/entity-representative', () => ({
  extractEntityRepresentativeName: vi.fn(),
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

vi.mock('../../../src/database/redis/token_usage', () => ({
  getTokensUsage: vi.fn(async () => []),
  updateTokenUsage: vi.fn(),
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    isFeatureEnabled: vi.fn(() => true),
    logApp: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
});

vi.mock('../../../src/config/errors', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return { ...actual };
});

vi.mock('../../../src/http/ipWhitelistMiddleware', () => ({
  ipMatchesWhitelist: vi.fn(),
  isUserExcluded: vi.fn(),
}));

describe('User domain - cache reset on password validity changes', () => {
  beforeEach(() => {
    mockElRawUpdateByQuery.mockClear();
    mockPublishCacheResetEvent.mockClear();
  });

  it('clearAllUsersPasswordValidUntil should call publishCacheResetEvent with ENTITY_TYPE_USER', async () => {
    const { clearAllUsersPasswordValidUntil } = await import('../../../src/domain/user');

    await clearAllUsersPasswordValidUntil({});

    expect(mockElRawUpdateByQuery).toHaveBeenCalledTimes(1);
    expect(mockPublishCacheResetEvent).toHaveBeenCalledTimes(1);
    expect(mockPublishCacheResetEvent).toHaveBeenCalledWith('User');
  });

  it('adjustAllUsersPasswordValidUntil should call publishCacheResetEvent with ENTITY_TYPE_USER (from disabled)', async () => {
    const { adjustAllUsersPasswordValidUntil } = await import('../../../src/domain/user');

    await adjustAllUsersPasswordValidUntil({}, 0, 30);

    // One call for setting fresh expiry on all users (from disabled state)
    expect(mockElRawUpdateByQuery).toHaveBeenCalledTimes(1);
    expect(mockPublishCacheResetEvent).toHaveBeenCalledTimes(1);
    expect(mockPublishCacheResetEvent).toHaveBeenCalledWith('User');
  });

  it('adjustAllUsersPasswordValidUntil should call publishCacheResetEvent with ENTITY_TYPE_USER (active shift)', async () => {
    const { adjustAllUsersPasswordValidUntil } = await import('../../../src/domain/user');

    await adjustAllUsersPasswordValidUntil({}, 60, 30);

    // Two calls: one to shift existing, one to set fresh for users without expiry
    expect(mockElRawUpdateByQuery).toHaveBeenCalledTimes(2);
    expect(mockPublishCacheResetEvent).toHaveBeenCalledTimes(1);
    expect(mockPublishCacheResetEvent).toHaveBeenCalledWith('User');
  });

  it('adjustAllUsersPasswordValidUntil should not call publishCacheResetEvent when diff is 0', async () => {
    const { adjustAllUsersPasswordValidUntil } = await import('../../../src/domain/user');

    await adjustAllUsersPasswordValidUntil({}, 30, 30);

    expect(mockElRawUpdateByQuery).not.toHaveBeenCalled();
    expect(mockPublishCacheResetEvent).not.toHaveBeenCalled();
  });
});
