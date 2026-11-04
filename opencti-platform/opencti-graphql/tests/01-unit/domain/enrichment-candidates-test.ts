import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createEntityAutoEnrichment, updateEntityAutoEnrichment } from '../../../src/domain/enrichment';
import { getEntitiesListFromCache } from '../../../src/database/cache';
import { redisGetConnectorsHeartbeats } from '../../../src/modules/connector/connector-redis';
import { CONNECTOR_INTERNAL_ENRICHMENT } from '../../../src/schema/general';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import type { AuthContext, AuthUser } from '../../../src/types/user';

// ---------------------------------------------------------------------------
// OpenCTI-Platform/opencti#18853: liveness is not part of the connectors cache,
// auto-enrichment computes it from the heartbeats in redis. Heartbeats must only
// be read when a connector could be triggered by the write, not for every
// enrichment connector in scope.
// ---------------------------------------------------------------------------

vi.mock('../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/cache')>()),
  getEntitiesListFromCache: vi.fn(),
}));

vi.mock('../../../src/modules/connector/connector-redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/connector/connector-redis')>()),
  redisGetConnectorsHeartbeats: vi.fn(),
}));

const testContext = { source: 'test' } as unknown as AuthContext;
const testUser = { id: 'test-user-id' } as unknown as AuthUser;
const element = { entity_type: ENTITY_TYPE_MALWARE, standard_id: 'malware--4a3b5c1d-0000-4000-8000-000000000000' };
const stixLoaders = { loadById: vi.fn(), bundleById: vi.fn() };

const enrichmentConnector = {
  id: 'enrichment-1',
  internal_id: 'enrichment-1',
  name: 'Enrichment connector',
  connector_type: CONNECTOR_INTERNAL_ENRICHMENT,
  connector_scope: [ENTITY_TYPE_MALWARE],
  connector_user_id: 'connector-user-id',
  auto: false,
  auto_update: false,
  connector_trigger_filters: '',
};

const enrich = (mode: 'creation' | 'update') => {
  return mode === 'creation'
    ? createEntityAutoEnrichment(testContext, testUser, element, ENTITY_TYPE_MALWARE, stixLoaders)
    : updateEntityAutoEnrichment(testContext, testUser, element, ENTITY_TYPE_MALWARE, stixLoaders);
};

describe('auto-enrichment candidates', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // No heartbeat: connectors are inactive, nothing is published
    vi.mocked(redisGetConnectorsHeartbeats).mockResolvedValue(new Map());
  });

  it.each([
    { mode: 'update' as const, flags: { auto: true } },
    { mode: 'creation' as const, flags: { auto_update: true } },
  ])('should not read heartbeats in $mode mode when no connector can be triggered', async ({ mode, flags }) => {
    vi.mocked(getEntitiesListFromCache).mockResolvedValueOnce([{ ...enrichmentConnector, ...flags }] as never);

    expect(await enrich(mode)).toEqual([]);
    expect(redisGetConnectorsHeartbeats).not.toHaveBeenCalled();
  });

  it.each([
    { mode: 'update' as const, flags: { auto_update: true } },
    { mode: 'creation' as const, flags: { auto: true } },
    { mode: 'creation' as const, flags: { connector_trigger_filters: '{"mode":"and","filters":[],"filterGroups":[]}' } },
  ])('should read heartbeats in $mode mode when a connector can be triggered by $flags', async ({ mode, flags }) => {
    vi.mocked(getEntitiesListFromCache).mockResolvedValueOnce([{ ...enrichmentConnector, ...flags }] as never);

    expect(await enrich(mode)).toEqual([]);
    expect(redisGetConnectorsHeartbeats).toHaveBeenCalledTimes(1);
  });

  it('should not read heartbeats for connectors out of scope', async () => {
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([{ ...enrichmentConnector, auto: true, auto_update: true, connector_scope: ['Report'] }] as never);

    expect(await enrich('creation')).toEqual([]);
    expect(await enrich('update')).toEqual([]);
    expect(redisGetConnectorsHeartbeats).not.toHaveBeenCalled();
  });
});
