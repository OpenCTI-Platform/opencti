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
import * as cache from '../../../src/database/cache';
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
// Grants every element it is given, as for a user with the bypass capability
const grantAll = () => vi.spyOn(accessModule, 'userFilterStoreElements').mockImplementation(async (_context, _user, elements) => elements);

// ── convertAggregateDistributions: lines 778-780 and 792 ────────────────────

describe('convertAggregateDistributions via distributionEntities (field=creator_id)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should assign entity: null for the "unknown" bucket without checking its access', async () => {
    const accessSpy = grantAll();

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

    // The access is checked once, for the real entity only: the 'unknown' bucket has none
    expect(accessSpy).toHaveBeenCalledTimes(1);
    expect(accessSpy.mock.calls[0][2].map((e) => e.internal_id)).toEqual([ENTITY_ID_1]);
  });

  it('should include the "unknown" bucket in the result even if it has no backing entity', async () => {
    grantAll();

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

  it('returns a restricted entity with an obfuscated standard_id when access is denied', async () => {
    vi.spyOn(accessModule, 'userFilterStoreElements').mockResolvedValue([]);

    vi.mocked(engine.elAggregationCount).mockResolvedValue([
      { label: ENTITY_ID_1, value: 4 },
    ] as any);

    const entity = {
      ...makeEntity(ENTITY_ID_1, 'Secret Org'),
      standard_id: 'identity--d4551de9-4b9c-570e-a51c-d3c321eb9a8d',
    };
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      [ENTITY_ID_1]: entity,
    } as any);

    const result = await distributionEntities(mockContext, accessModule.SYSTEM_USER, ['Threat-Actor'], {
      field: 'creator_id',
      limit: 10,
      order: 'desc',
    } as any);

    expect(result[0].entity?.name).toBe('Restricted');
    // standard_id must stay obfuscated: exposing the real id would leak the
    // entity's identity to a user who has no access to it.
    expect((result[0].entity as any)?.standard_id).toBe('Restricted');
  });

  it('checks the access of every value at once, with the markings of the user', async () => {
    // Not mocked (the implementations of the tests above are restored): a user without the bypass capability,
    // allowed to see the green marking only
    vi.restoreAllMocks();
    const accessSpy = vi.spyOn(accessModule, 'userFilterStoreElements');
    vi.mocked(cache.getEntityFromCache).mockResolvedValue({ platform_organization: undefined } as any);
    const analyst = {
      id: 'analyst-id',
      internal_id: 'analyst-id',
      capabilities: [{ name: 'KNOWLEDGE' }],
      allowed_marking: [{ internal_id: 'marking-green' }],
      groups: [],
      organizations: [],
    } as any;
    const green = { ...makeEntity('entity-green', 'Green Actor'), 'object-marking': ['marking-green'] };
    const red = { ...makeEntity('entity-red', 'Red Actor'), 'object-marking': ['marking-red'] };
    const unmarked = makeEntity('entity-unmarked', 'Unmarked Actor');
    vi.mocked(engine.elAggregationCount).mockResolvedValue([
      { label: 'entity-red', value: 9 },
      { label: 'unknown', value: 7 },
      { label: 'entity-green', value: 5 },
      { label: 'entity-unmarked', value: 3 },
    ] as any);
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'entity-green': green, 'entity-red': red, 'entity-unmarked': unmarked } as any);

    const result = await distributionEntities(mockContext, analyst, ['Threat-Actor'], { field: 'creator_id', limit: 10, order: 'desc' } as any);

    expect(accessSpy).toHaveBeenCalledTimes(1);
    expect(result.map((r) => [r.label, r.value, r.entity?.name ?? null])).toEqual([
      ['entity-red', 9, 'Restricted'],
      ['unknown', 7, null],
      ['entity-green', 5, 'Green Actor'],
      ['entity-unmarked', 3, 'Unmarked Actor'],
    ]);
    // The restricted entity keeps its id and type only
    expect(result[0].entity).toMatchObject({ id: 'entity-red', entity_type: 'Threat-Actor', representative: { main: 'Restricted' } });
    expect(result[2].entity).toBe(green);
  });
});

// ── distributionEntities name branch: lines 902-906 ──────────────────────────

describe('distributionEntities (field=name) — safe entity?.name access', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    grantAll();
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
    grantAll();
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
