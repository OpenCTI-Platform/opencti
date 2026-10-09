import { vi } from 'vitest';

/**
 * Shared base mock factory for '../../src/database/cache', meant to be reused by every test that
 * (transitively) imports src/manager/cacheManager.ts.
 *
 * cacheManager.ts reads STORE_ENTITIES_LINKS at module-evaluation time (to compute which pub/sub
 * topics it needs to subscribe to). Any partial vi.mock of database/cache used alongside it MUST
 * provide this export - otherwise `Object.keys(STORE_ENTITIES_LINKS)` throws as soon as the module
 * is evaluated, and every test in the file fails before it even runs.
 *
 * Usage:
 *   vi.mock('../../../src/database/cache', () => createDatabaseCacheMock({
 *     writeCacheForEntity: (...args) => mockWriteCacheForEntity(...args),
 *   }));
 */
export const createDatabaseCacheMock = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  STORE_ENTITIES_LINKS: {},
  writeCacheForEntity: vi.fn(),
  resetCacheForEntity: vi.fn(),
  addCacheForEntity: vi.fn(),
  refreshCacheForEntity: vi.fn(),
  removeCacheForEntity: vi.fn(),
  ...overrides,
});
