import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Infrastructure stubs ─────────────────────────────────────────────────────

vi.mock('../../../src/database/engine');
vi.mock('../../../src/database/redis', () => ({ notify: vi.fn(), redisAddDeletions: vi.fn() }));
vi.mock('../../../src/database/cache', () => ({
  getEntitiesMapFromCache: vi.fn(),
  getEntityFromCache: vi.fn(),
}));
vi.mock('../../../src/database/stream/stream-handler', () => ({
  storeCreateEntityEvent: vi.fn(),
  storeCreateRelationEvent: vi.fn(),
  storeDeleteEvent: vi.fn(),
  storeMergeEvent: vi.fn(),
  storeUpdateEvent: vi.fn(),
}));
vi.mock('../../../src/database/file-search', () => ({
  elUpdateRemovedFiles: vi.fn(),
}));
vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));
vi.mock('../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../src/config/conf');
  return {
    ...(actual as object),
    logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
    extendedErrors: false,
    BUS_TOPICS: {},
  };
});

// ── Imports (after mocks) ────────────────────────────────────────────────────

import * as engine from '../../../src/database/engine';
import * as accessModule from '../../../src/utils/access';
import { distributionEntities, distributionHistory } from '../../../src/database/middleware';

// ── Shared fixtures ──────────────────────────────────────────────────────────

const mockContext = { user: accessModule.SYSTEM_USER } as any;
const ENTITY_ID_1 = 'entity-id-aaaa';

/** Minimal BasicStoreEntity shape returned by elFindByIds */
const makeEntity = (id: string, name: string) => ({
  id,
  internal_id: id,
  entity_type: 'Threat-Actor',
  name,
  parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Threat-Actor'],
  representative: { main: name, secondary: '' },
});

// ── convertAggregateDistributions: lines 778-780 and 792 ────────────────────

describe('convertAggregateDistributions via distributionEntities (field=creator_id)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should assign entity: null for the "unknown" bucket without calling isUserCanAccessStoreElement', async () => {
    const isAccessSpy = vi.spyOn(accessModule, 'isUserCanAccessStoreElement').mockResolvedValue(true);

    // elAggregationCount returns one 'unknown' bucket and one real entity bucket
    vi.mocked(engine.elAggregationCount).mockResolvedValue([
      { label: ENTITY_ID_1, value: 10 },
      { label: 'unknown', value: 3 },
    ] as any);

    // elFindByIds resolves only the real entity (not 'unknown' — there is no backing entity)
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      [ENTITY_ID_1]: makeEntity(ENTITY_ID_1, 'Threat Actor One'),
    } as any);

    const result = await distributionEntities(mockContext, accessModule.SYSTEM_USER, ['Threat-Actor'], {
      field: 'creator_id',
      limit: 10,
      order: 'desc',
    } as any);

    // The 'unknown' bucket must produce entity: null
    const unknownResult = result.find((r) => r.label === 'unknown');
    expect(unknownResult).toBeDefined();
    expect(unknownResult?.entity).toBeNull();

    // isUserCanAccessStoreElement must NOT have been called for the 'unknown' bucket
    // (it should only be called for the real entity)
    const callArgs = isAccessSpy.mock.calls.map((c) => c[2]);
    expect(callArgs.every((e) => e !== null && (e as any).id !== 'unknown')).toBe(true);
    expect(isAccessSpy).toHaveBeenCalledTimes(1); // only for the real entity
  });

  it('should include the "unknown" bucket in the result even if it has no backing entity', async () => {
    vi.spyOn(accessModule, 'isUserCanAccessStoreElement').mockResolvedValue(true);

    vi.mocked(engine.elAggregationCount).mockResolvedValue([
      { label: 'unknown', value: 7 },
    ] as any);
    // elFindByIds returns nothing (no real entity for 'unknown')
    vi.mocked(engine.elFindByIds).mockResolvedValue({} as any);

    const result = await distributionEntities(mockContext, accessModule.SYSTEM_USER, ['Threat-Actor'], {
      field: 'creator_id',
      limit: 10,
      order: 'desc',
    } as any);

    expect(result).toHaveLength(1);
    expect(result[0].label).toBe('unknown');
    expect(result[0].value).toBe(7);
    expect(result[0].entity).toBeNull();
  });
});

// ── distributionEntities name branch: lines 902-906 ──────────────────────────

describe('distributionEntities (field=name) — safe entity?.name access', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(accessModule, 'isUserCanAccessStoreElement').mockResolvedValue(true);
  });

  it('uses the entity name as label when entity is present', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([
      { label: ENTITY_ID_1, value: 5 },
    ] as any);

    const entity = makeEntity(ENTITY_ID_1, 'Threat Actor One');
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      [ENTITY_ID_1]: entity,
    } as any);

    const result = await distributionEntities(mockContext, accessModule.SYSTEM_USER, ['Threat-Actor'], {
      field: 'name',
      limit: 10,
      order: 'desc',
    } as any);

    expect(result).toHaveLength(1);
    expect(result[0].label).toBe('Threat Actor One');
    expect(result[0].entity).toEqual(entity);
  });
});

// ── distributionHistory name branch: lines 838-859 ───────────────────────────

describe('distributionHistory (field=name) — safe entity?.name access', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(accessModule, 'isUserCanAccessStoreElement').mockResolvedValue(true);
  });

  it('uses the entity name as label when entity is present', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([
      { label: ENTITY_ID_1, value: 8 },
    ] as any);

    const entity = makeEntity(ENTITY_ID_1, 'History Actor');
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      [ENTITY_ID_1]: entity,
    } as any);

    const result = await distributionHistory(mockContext, accessModule.SYSTEM_USER, {
      field: 'name',
      limit: 10,
      order: 'desc',
    } as any);

    expect(result).toHaveLength(1);
    expect((result as any[])[0].label).toBe('History Actor');
  });
});
