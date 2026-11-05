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

// The registered schema, for the checks of the date attributes
import '../../../src/modules/index';
import * as engine from '../../../src/database/engine';
import * as accessModule from '../../../src/utils/access';
import {
  BREAKDOWN_ALLOWED_REFS,
  checkBreakdownDateAttribute,
  distributionEntities,
  distributionHistory,
  HISTORY_BREAKDOWN_ALLOWED_FIELDS,
  normalizeEnumValue,
  resolveBreakdownField,
  resolveHistoryBreakdownField,
  resolveRelationshipBreakdownField,
  timeSeriesBreakdownEntities,
  timeSeriesBreakdownHistory,
  timeSeriesBreakdownRelations,
} from '../../../src/database/middleware';
import { stixRelationshipsMultiTimeSeries, stixRelationshipsTimeSeriesBreakdown } from '../../../src/domain/stixRelationship';
import { BREAKDOWN_REFUSAL_REASONS, INDEX_INFERRED_RELATIONSHIPS, READ_INDEX_HISTORY, READ_INDEX_STIX_META_OBJECTS, READ_RELATIONSHIPS_INDICES } from '../../../src/database/utils';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';
import { READ_ENTITIES_INDICES, READ_INDEX_INFERRED_ENTITIES } from '../../../src/database/utils';
import { FunctionalError } from '../../../src/config/errors';
import stixObjectOrStixRelationshipOrCreatorResolvers from '../../../src/resolvers/stixObjectOrStixRelationshipOrCreator';

// ── Shared fixtures ──────────────────────────────────────────────────────────

const mockContext = { user: accessModule.SYSTEM_USER } as any;
// Noon UTC keeps the same calendar day in any timezone the tests may run in
const startDate = new Date('2026-01-01T12:00:00.000Z');
const endDate = new Date('2026-01-03T12:00:00.000Z');

const makeEntity = (id: string, name: string) => ({
  id,
  internal_id: id,
  entity_type: 'User',
  name,
  parent_types: ['Basic-Object', 'Internal-Object', 'User'],
  representative: { main: name, secondary: '' },
});

const bucket = (key: string, value: number) => ({ key, label: key, value, count: value });
type Bucket = ReturnType<typeof bucket>;
// Result of the rankings: the values kept by the size cap, and the documents of the values left out
const ranking = (buckets: Bucket[], sumOtherDocCount = 0) => ({ buckets, sumOtherDocCount });
type Points = { date: string; value: number }[];
// Result of elHistogramBreakdownCount: the histogram of each key, and apart the one of Other when it is requested
const histogramsOf = (entries: [string, Points][] = [], other: Points | null = null) => ({ histograms: new Map(entries), other });

// Registered entity types, as their lowercase indexed form is resolved
const REGISTERED_TYPES = ['History', 'Activity', 'Report', 'Malware', 'Intrusion-Set', 'Sector', 'Country', 'Organization', 'IMEI', 'SecurityPlatform', 'PublicDashboard', 'uses'];
const mockRegisteredTypes = () => vi.spyOn(schemaAttributesDefinition, 'getRegisteredTypes').mockReturnValue(REGISTERED_TYPES);
// Refusal of the engine when the lowest values cannot be ranked exactly
const tooManyValuesError = () => FunctionalError('Too many values to rank the lowest ones, narrow the filters or the period', {
  reason: 'too_many_values',
  max: engine.MAX_EXACT_RANKING_SIZE,
});

// Minimal schema: Reports carry every field below, Malwares have no report types
const REFS: Record<string, string> = {
  objectLabel: 'object-label',
  objectAssignee: 'object-assignee',
  createdBy: 'created-by',
  objects: 'object',
  externalReferences: 'external-reference',
};
const ATTRIBUTES: Record<string, { type: string; format?: string; vocabularyCategory?: string; values?: string[] }> = {
  creator_id: { type: 'string', format: 'id' },
  pir_ids: { type: 'string', format: 'id' },
  report_types: { type: 'string', format: 'vocabulary', vocabularyCategory: 'report_types_ov' },
  x_opencti_cvss_base_severity: { type: 'string', format: 'enum', values: ['CRITICAL', 'HIGH', 'Unknown'] },
  description: { type: 'string', format: 'text' },
  published: { type: 'date' },
};
const mockSchema = () => {
  vi.spyOn(schemaRelationsRefDefinition, 'getRelationRef').mockImplementation((_type, name) => (
    name && REFS[name] ? { name, databaseName: REFS[name] } as any : null
  ));
  vi.spyOn(schemaAttributesDefinition, 'getAttribute').mockImplementation((type, name) => {
    if (type === 'Malware' && name === 'report_types') return undefined;
    return ATTRIBUTES[name] ? { name, isFilterable: true, ...ATTRIBUTES[name] } as any : undefined;
  });
};

const breakdown = (args: Record<string, unknown>) => timeSeriesBreakdownEntities(mockContext, accessModule.SYSTEM_USER, ['Report'], {
  startDate,
  endDate,
  interval: 'day',
  ...args,
} as any);

describe('timeSeriesBreakdownEntities', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(accessModule, 'userFilterStoreElements').mockImplementation(async (_context, _user, elements) => elements);
    vi.mocked(engine.elKeywordWrittenForms).mockResolvedValue(new Map());
    mockSchema();
    mockRegisteredTypes();
  });

  it('should reject a limit out of bounds', async () => {
    await expect(breakdown({ field: 'creator_id', limit: 0 })).rejects.toThrow('Time series breakdown limit');
    await expect(breakdown({ field: 'creator_id', limit: 51 })).rejects.toThrow('Time series breakdown limit');
    for (const limit of [0, 51, 2.5]) {
      await expect(breakdown({ field: 'creator_id', limit })).rejects.toMatchObject({
        extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'invalid_limit', limit, max: 50 } },
      });
    }
    expect(engine.elAggregationRanking).not.toHaveBeenCalled();
  });

  it('should reject fields that cannot be broken down', async () => {
    await expect(breakdown({ field: 'description' })).rejects.toThrow('does not support this field');
    await expect(breakdown({ field: 'published' })).rejects.toThrow('does not support this field');
    await expect(breakdown({ field: 'regardingOf' })).rejects.toThrow('does not support this field');
    await expect(breakdown({ field: 'description' })).rejects.toMatchObject({
      extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'unsupported_field', field: 'description', types: ['Report'] } },
    });
    expect(engine.elAggregationRanking).not.toHaveBeenCalled();
  });

  it('should reject relation refs outside the allowlist', async () => {
    await expect(breakdown({ field: 'objects' })).rejects.toThrow('does not support this field');
    await expect(breakdown({ field: 'externalReferences' })).rejects.toThrow('does not support this field');
    expect(engine.elAggregationRanking).not.toHaveBeenCalled();
  });

  it('should refuse a date attribute that is not a date of the types, before querying', async () => {
    // Given to the engine as the field of the date histogram, a text or an unknown field would make it fail
    for (const dateAttribute of ['description', 'creator_id', 'report_types', 'not_an_attribute']) {
      await expect(breakdown({ field: 'creator_id', dateAttribute })).rejects.toMatchObject({
        extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'unsupported_date_attribute', dateAttribute, types: ['Report'] } },
      });
    }
    expect(engine.elAggregationRanking).not.toHaveBeenCalled();
    expect(engine.elHistogramBreakdownCount).not.toHaveBeenCalled();
  });

  it('should count the entities on their creation date without date attribute', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('user-a', 1)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'user-a': makeEntity('user-a', 'Alice') } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    for (const dateAttribute of [undefined, null, '']) {
      await breakdown({ field: 'creator_id', dateAttribute });
      expect((vi.mocked(engine.elAggregationRanking).mock.lastCall?.[3] as any).dateAttribute).toEqual('created_at');
      expect((vi.mocked(engine.elHistogramBreakdownCount).mock.lastCall?.[3] as any).dateAttribute).toEqual('created_at');
    }
  });

  it('should count the Other series in the maximum number of buckets', async () => {
    // 50 series over 1,000 days fit in 50,000 buckets, 51 do not
    const thousandDaysLater = new Date('2028-09-26T12:00:00.000Z');
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());
    await expect(breakdown({ field: 'creator_id', limit: 50, endDate: thousandDaysLater, includeOther: true })).rejects.toThrow('too large');
    await expect(breakdown({ field: 'creator_id', limit: 50, endDate: thousandDaysLater })).resolves.toBeDefined();
  });

  it('should give the reason and the size of a breakdown refused as too large', async () => {
    const threeYearsLater = new Date('2029-01-01T12:00:00.000Z');
    // The front tests the reason, not the message
    await expect(breakdown({ field: 'creator_id', limit: 50, endDate: threeYearsLater })).rejects.toMatchObject({
      extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'too_large', limit: 50, intervalsCount: 1097, max: 50000 } },
    });
  });

  it('should keep the values with the lowest total in asc order', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([
      bucket('user-a', 10),
      bucket('user-b', 5),
      bucket('user-c', 3),
      bucket('user-d', 1),
    ]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'user-a': makeEntity('user-a', 'Alice'),
      'user-b': makeEntity('user-b', 'Bob'),
      'user-c': makeEntity('user-c', 'Carol'),
      'user-d': makeEntity('user-d', 'Dave'),
    } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'creator_id', limit: 2, orderMode: 'asc' });

    expect(result.truncated).toBe(true);
    expect(result.series.map((serie) => (serie.entity as any)?.name)).toEqual(['Dave', 'Carol']);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['user-d', 'user-c']);
  });

  it('should rank the candidates on their weighted total, in the order of the selection', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('user-a', 10)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'user-a': makeEntity('user-a', 'Alice') } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    await breakdown({ field: 'creator_id', orderMode: 'asc' });
    expect(vi.mocked(engine.elAggregationRanking).mock.lastCall?.[3]).toMatchObject({ rankingOrder: 'asc' });

    for (const order of ['desc', null, undefined]) {
      await breakdown({ field: 'creator_id', orderMode: order });
      expect(vi.mocked(engine.elAggregationRanking).mock.lastCall?.[3]).toMatchObject({ rankingOrder: 'desc' });
    }
  });

  it('should rank the values on the weighted totals the series count, inferred documents included', async () => {
    // user-b has fewer entities than user-a (doc counts 2 and 3) but more weight: it comes first, as its total does
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([
      { key: 'user-b', label: 'user-b', value: 6, count: 2 },
      { key: 'user-a', label: 'user-a', value: 3, count: 3 },
    ]));
    vi.mocked(engine.elFindByIds).mockImplementation(async (_context, _user, ids) => Object.fromEntries(
      (ids as string[]).map((id) => [id, makeEntity(id, id)]),
    ) as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf([
      ['user-a', [{ date: '2026-01-01', value: 3 }]],
      ['user-b', [{ date: '2026-01-02', value: 6 }]],
    ]));

    const desc = await breakdown({ field: 'creator_id', limit: 1 });
    expect(desc.series.map((serie) => [serie.label, serie.total])).toEqual([['user-b', 6]]);
    expect(desc.truncated).toBe(true);
  });

  it('should give each series its weighted total from the histogram', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('user-a', 10)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'user-a': makeEntity('user-a', 'Alice') } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf([
      ['user-a', [{ date: '2026-01-01', value: 2 }, { date: '2026-01-03', value: 1.5 }]],
    ]));

    const result = await breakdown({ field: 'creator_id' });

    expect(result.series[0].values).toEqual([2, 0, 1.5]);
    expect(result.series[0].total).toEqual(3.5);
  });

  it('should use one filter per value in the histogram only when the field has many values', async () => {
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());
    const types = (count: number) => Array.from({ length: count }, (_, i) => ({ key: `type-${i}`, label: `Type-${i}`, value: 100 - i, count: 100 - i }));

    // A handful of values: the restricted terms aggregation is faster
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking(types(5)));
    await breakdown({ field: 'entity_type', limit: 5 });
    expect((vi.mocked(engine.elHistogramBreakdownCount).mock.lastCall?.[3] as any).filterPerKey).toBe(false);

    // Three times more values than series
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking(types(15)));
    await breakdown({ field: 'entity_type', limit: 5 });
    expect((vi.mocked(engine.elHistogramBreakdownCount).mock.lastCall?.[3] as any).filterPerKey).toBe(true);

    // A full candidates page, whatever the limit
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking(types(engine.MAX_AGGREGATION_SIZE)));
    await breakdown({ field: 'entity_type', limit: 50 });
    expect((vi.mocked(engine.elHistogramBreakdownCount).mock.lastCall?.[3] as any).filterPerKey).toBe(true);
  });

  it('should only resolve the candidates needed to fill the limit and know whether more exist', async () => {
    const users = Array.from({ length: 40 }, (_, i) => `user-${i}`);
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking(users.map((id, i) => bucket(id, 100 - i))));
    vi.mocked(engine.elFindByIds).mockImplementation(async (_context, _user, ids) => Object.fromEntries(
      (ids as string[]).map((id) => [id, makeEntity(id, id)]),
    ) as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'creator_id', limit: 5 });

    // limit + 10 values at once, enough to fill the limit and see a sixth one
    expect(engine.elFindByIds).toHaveBeenCalledTimes(1);
    expect(vi.mocked(engine.elFindByIds).mock.calls[0][2]).toEqual(users.slice(0, 15));
    expect(result.series).toHaveLength(5);
    expect(result.truncated).toBe(true);
  });

  it('should resolve the next candidates when the first ones cannot be resolved', async () => {
    const users = Array.from({ length: 30 }, (_, i) => `user-${i}`);
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking(users.map((id, i) => bucket(id, 100 - i))));
    // The 13 first values are unknown entities (like deleted users)
    vi.mocked(engine.elFindByIds).mockImplementation(async (_context, _user, ids) => Object.fromEntries(
      (ids as string[]).filter((id) => Number(id.split('-')[1]) >= 13).map((id) => [id, makeEntity(id, id)]),
    ) as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'creator_id', limit: 2 });

    expect(engine.elFindByIds).toHaveBeenCalledTimes(2);
    expect(result.series.map((serie) => serie.label)).toEqual(['user-13', 'user-14']);
    expect(result.truncated).toBe(true);
  });

  it('should double the page of the candidates resolved at each round', async () => {
    // 200 candidates of which the last one only is an entity
    const users = Array.from({ length: 200 }, (_, i) => `user-${i}`);
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking(users.map((id, i) => bucket(id, 1000 - i))));
    vi.mocked(engine.elFindByIds).mockImplementation(async (_context, _user, ids) => Object.fromEntries(
      (ids as string[]).filter((id) => id === 'user-199').map((id) => [id, makeEntity(id, id)]),
    ) as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'creator_id', limit: 5 });

    // limit + 10, then twice as many at each round: 4 rounds instead of 14 pages of 15
    expect(vi.mocked(engine.elFindByIds).mock.calls.map(([, , ids]) => (ids as string[]).length)).toEqual([15, 30, 60, 95]);
    expect(vi.mocked(engine.elFindByIds).mock.calls.flatMap(([, , ids]) => ids as string[])).toEqual(users);
    expect(result.series.map((serie) => serie.label)).toEqual(['user-199']);
  });

  it('should keep the internal users as creators, never looked for nor restricted', async () => {
    const { SYSTEM_USER, AUTOMATION_MANAGER_USER } = accessModule;
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket(SYSTEM_USER.id, 9), bucket('user-a', 5), bucket(AUTOMATION_MANAGER_USER.id, 2)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'user-a': makeEntity('user-a', 'Alice') } as any);
    // The user can access none of the stored entities
    vi.mocked(accessModule.userFilterStoreElements).mockResolvedValue([]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'creator_id' });

    expect(vi.mocked(engine.elFindByIds).mock.calls[0][2]).toEqual(['user-a']);
    expect(result.series.map((serie) => [serie.label, (serie.entity as any)?.name])).toEqual([
      [SYSTEM_USER.id, 'SYSTEM'],
      ['user-a', 'Restricted'],
      [AUTOMATION_MANAGER_USER.id, AUTOMATION_MANAGER_USER.name],
    ]);
    // Shaped as the creators of the entities, the union of the entities resolving a user as a Creator
    expect(result.series[0].entity).toEqual({
      id: SYSTEM_USER.id,
      internal_id: SYSTEM_USER.id,
      standard_id: SYSTEM_USER.id,
      entity_type: 'User',
      parent_types: ['Basic-Object', 'Internal-Object'],
      name: 'SYSTEM',
    });
    expect(stixObjectOrStixRelationshipOrCreatorResolvers.StixObjectOrStixRelationshipOrCreator.__resolveType(result.series[0].entity)).toEqual('Creator');
  });

  it('should only query the entities indices', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([]));

    await breakdown({ field: 'entity_type' });
    expect(vi.mocked(engine.elAggregationRanking).mock.lastCall?.[2]).toEqual(READ_ENTITIES_INDICES);

    await breakdown({ field: 'entity_type', onlyInferred: true });
    expect(vi.mocked(engine.elAggregationRanking).mock.lastCall?.[2]).toEqual([READ_INDEX_INFERRED_ENTITIES]);
  });

  it('should keep a vocabulary value named unknown like any other value', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('unknown', 50), bucket('malicious-activity', 10)]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'report_types' });

    expect(result.series.map((serie) => serie.label)).toEqual(['unknown', 'malicious-activity']);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['unknown', 'malicious-activity']);
  });

  it('should keep the distribution APIs out of the ranking, their order only sorting their result', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([]);
    await distributionEntities(mockContext, accessModule.SYSTEM_USER, ['Report'], { field: 'entity_type', order: 'asc', limit: 10 } as any);
    await distributionHistory(mockContext, accessModule.SYSTEM_USER, { field: 'entity_type', order: 'descending', limit: 10 } as any);
    expect(engine.elAggregationCount).toHaveBeenCalledTimes(2);
    expect(engine.elAggregationRanking).not.toHaveBeenCalled();
  });

  it('should keep the values with the highest total when the order is desc or not given', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('user-c', 3), bucket('user-a', 10), bucket('user-b', 5)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'user-a': makeEntity('user-a', 'Alice'),
      'user-b': makeEntity('user-b', 'Bob'),
      'user-c': makeEntity('user-c', 'Carol'),
    } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    for (const order of ['desc', null, undefined]) {
      const result = await breakdown({ field: 'creator_id', limit: 2, orderMode: order });
      expect(result.series.map((serie) => (serie.entity as any)?.name)).toEqual(['Alice', 'Bob']);
    }
  });

  it('should not be truncated in asc when every usable value fits and the candidates page is not full', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('user-a', 10), bucket('user-b', 5)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'user-a': makeEntity('user-a', 'Alice'),
      'user-b': makeEntity('user-b', 'Bob'),
    } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'creator_id', limit: 10, orderMode: 'asc' });

    expect(result.truncated).toBe(false);
  });

  it('should keep the lowest values first in asc order, truncated when more values are usable than the limit', async () => {
    const candidates = Array.from({ length: engine.MAX_AGGREGATION_SIZE }, (_, i) => bucket(`report-${i}`, 100 - i));
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking(candidates));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'entity_type', limit: 50, orderMode: 'asc' });

    expect(result.truncated).toBe(true);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys[0]).toEqual(`report-${engine.MAX_AGGREGATION_SIZE - 1}`);
  });

  it('should flag as truncated the values the ranking left out, and only them', async () => {
    // As many candidates as a full desc page, only two of them usable
    const users = Array.from({ length: engine.MAX_AGGREGATION_SIZE }, (_, i) => `user-${i}`);
    const candidates = users.map((id, i) => bucket(id, 100 - i));
    vi.mocked(engine.elFindByIds).mockImplementation(async (_context, _user, ids) => Object.fromEntries(
      (ids as string[]).filter((id) => id === 'user-0' || id === 'user-1').map((id) => [id, makeEntity(id, id)]),
    ) as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    // Every value is there: exactly as many values as the size cap is not more
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking(candidates));
    for (const orderMode of ['asc', 'desc']) {
      const result = await breakdown({ field: 'creator_id', limit: 10, orderMode });
      expect(result.series).toHaveLength(2);
      expect(result.truncated).toBe(false);
    }

    // Documents of values left out of the desc ranking
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking(candidates, 12));
    const desc = await breakdown({ field: 'creator_id', limit: 10, orderMode: 'desc' });
    expect(desc.series.map((serie) => serie.label)).toEqual(['user-0', 'user-1']);
    expect(desc.truncated).toBe(true);
  });

  it('should only resolve the lowest candidates needed among every value ranked in asc order', async () => {
    const users = Array.from({ length: engine.MAX_EXACT_RANKING_SIZE }, (_, i) => `user-${i}`);
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking(users.map((id, i) => bucket(id, i + 1))));
    vi.mocked(engine.elFindByIds).mockImplementation(async (_context, _user, ids) => Object.fromEntries(
      (ids as string[]).map((id) => [id, makeEntity(id, id)]),
    ) as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'creator_id', limit: 5, orderMode: 'asc' });

    expect(engine.elFindByIds).toHaveBeenCalledTimes(1);
    expect(vi.mocked(engine.elFindByIds).mock.calls[0][2]).toEqual(users.slice(0, 15));
    expect(result.series.map((serie) => serie.label)).toEqual(users.slice(0, 5));
    expect(result.truncated).toBe(true);
  });

  it('should pass the refusal of the lowest values on to the caller, before any histogram', async () => {
    vi.mocked(engine.elAggregationRanking).mockRejectedValue(tooManyValuesError());

    await expect(breakdown({ field: 'creator_id', orderMode: 'asc' })).rejects.toMatchObject({
      extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'too_many_values', max: engine.MAX_EXACT_RANKING_SIZE } },
    });
    expect(engine.elFindByIds).not.toHaveBeenCalled();
    expect(engine.elHistogramBreakdownCount).not.toHaveBeenCalled();
  });

  it('should append the Other series last, computed from its own histogram', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('user-a', 10), bucket('user-b', 5)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'user-a': makeEntity('user-a', 'Alice'),
      'user-b': makeEntity('user-b', 'Bob'),
    } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf(
      [['user-a', [{ date: '2026-01-02', value: 4 }]]],
      [{ date: '2026-01-01', value: 2 }, { date: '2026-01-03', value: 5 }],
    ));

    const result = await breakdown({ field: 'creator_id', limit: 2, includeOther: true });

    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].withOther).toBe(true);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['user-a', 'user-b']);
    expect(engine.elHistogramBreakdownCount).toHaveBeenCalledTimes(1);
    expect(result.series.map((serie) => serie.isOther)).toEqual([false, false, true]);
    const other = result.series[2];
    expect(other.label).toEqual('Other');
    expect(other.entity).toBeNull();
    expect(other.total).toEqual(7);
    expect(other.values).toEqual([2, 0, 5]);
    // The dates are sent once, shared by every series
    expect(result.dates).toEqual(['2026-01-01T00:00:00.000Z', '2026-01-02T00:00:00.000Z', '2026-01-03T00:00:00.000Z']);
    expect(result.series.every((serie) => serie.values.length === result.dates.length)).toBe(true);
  });

  it('should keep a value named like a reserved key apart from the Other series', async () => {
    // A label may be named __other__: its series and Other are two histograms
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('__other__', 10), bucket('user-b', 5)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      __other__: makeEntity('__other__', 'Other label'),
      'user-b': makeEntity('user-b', 'Bob'),
    } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf(
      [['__other__', [{ date: '2026-01-01', value: 4 }]], ['user-b', [{ date: '2026-01-02', value: 1 }]]],
      [{ date: '2026-01-03', value: 7 }],
    ));

    const result = await breakdown({ field: 'creator_id', limit: 2, includeOther: true });

    expect(result.series.map((serie) => [serie.label, serie.isOther, serie.values])).toEqual([
      ['__other__', false, [4, 0, 0]],
      ['user-b', false, [0, 1, 0]],
      ['Other', true, [0, 0, 7]],
    ]);
  });

  it('should not add the Other series unless it is requested', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('user-a', 10)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'user-a': makeEntity('user-a', 'Alice') } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    for (const includeOther of [false, null, undefined]) {
      const result = await breakdown({ field: 'creator_id', includeOther });
      expect(result.series).toHaveLength(1);
      expect(result.series[0].isOther).toBe(false);
      expect(vi.mocked(engine.elHistogramBreakdownCount).mock.lastCall?.[3].withOther).toBe(false);
    }
  });

  it('should still count the Other series when no usable value is found', async () => {
    // Not resolvable, like the SYSTEM user
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('system', 3)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({} as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf([], [{ date: '2026-01-02', value: 3 }]));

    const result = await breakdown({ field: 'creator_id', includeOther: true });

    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual([]);
    expect(result.series.map((serie) => serie.label)).toEqual(['Other']);
    expect(result.series[0].total).toEqual(3);
  });

  it('should reject an unsupported interval before querying', async () => {
    await expect(breakdown({ field: 'creator_id', interval: 'minute' })).rejects.toThrow('Unsupported interval');
    expect(engine.elAggregationRanking).not.toHaveBeenCalled();
  });

  it('should end the period now when no end date is given', async () => {
    // Without it, the histogram would create a bucket for every day up to the most recent entity
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('user-a', 10)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'user-a': makeEntity('user-a', 'Alice') } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());
    const recentStartDate = new Date(Date.now() - 2 * 86400000);

    const before = Date.now();
    const result = await breakdown({ field: 'creator_id', startDate: recentStartDate, endDate: undefined });

    const histogramOptions = vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3] as any;
    expect(histogramOptions.endDate).toBeInstanceOf(Date);
    expect(histogramOptions.endDate.getTime()).toBeGreaterThanOrEqual(before);
    expect((vi.mocked(engine.elAggregationRanking).mock.calls[0][3] as any).endDate).toEqual(histogramOptions.endDate);
    expect(result.dates).toHaveLength(3);
  });

  it('should reject a breakdown exceeding the maximum number of buckets', async () => {
    const threeYearsLater = new Date('2029-01-01T12:00:00.000Z');
    await expect(breakdown({ field: 'creator_id', limit: 50, endDate: threeYearsLater })).rejects.toThrow('too large');
    expect(engine.elAggregationRanking).not.toHaveBeenCalled();
  });

  it('should drop unresolved values before applying the limit', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([
      bucket('user-a', 10),
      bucket('system', 7), // not resolvable, like the SYSTEM user
      bucket('user-b', 5),
      bucket('user-c', 3),
    ]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'user-a': makeEntity('user-a', 'Alice'),
      'user-b': makeEntity('user-b', 'Bob'),
      'user-c': makeEntity('user-c', 'Carol'),
    } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf([
      ['user-a', [{ date: '2026-01-02', value: 4 }]],
    ]));

    const result = await breakdown({ field: 'creator_id', limit: 2 });

    expect(result.truncated).toBe(true);
    expect(result.series.map((serie) => (serie.entity as any)?.name)).toEqual(['Alice', 'Bob']);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['user-a', 'user-b']);
    expect(result.series[0].values).toEqual([0, 4, 0]);
    // A value without any histogram bucket still gets a full zero series
    expect(result.series[1].values).toEqual([0, 0, 0]);
  });

  it('should not be truncated when every usable value fits in the limit', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('user-a', 10), bucket('system', 2)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'user-a': makeEntity('user-a', 'Alice') } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'creator_id', limit: 10 });

    expect(result.truncated).toBe(false);
    expect(result.series).toHaveLength(1);
  });

  it('should flag as truncated more values than the limit', async () => {
    const candidates = Array.from({ length: engine.MAX_AGGREGATION_SIZE }, (_, i) => bucket(`report-${i}`, 100 - i));
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking(candidates.map((c) => ({ ...c, label: `Report-${c.key}` }))));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'entity_type', limit: 50 });

    expect(result.truncated).toBe(true);
    expect(result.series).toHaveLength(50);
  });

  it('should name the vocabulary values after their vocabulary, read for the values kept only', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('reseau interne', 9), bucket('threat-report', 5), bucket('no-vocabulary', 3), bucket('dropped', 1)]));
    vi.mocked(engine.elKeywordWrittenForms).mockResolvedValue(new Map([['reseau interne', 'Réseau Interne'], ['threat-report', 'threat-report']]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'report_types', limit: 3 });

    // A value without vocabulary keeps its indexed form
    expect(result.series.map((serie) => serie.label)).toEqual(['Réseau Interne', 'threat-report', 'no-vocabulary']);
    // The histogram still targets the indexed values
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['reseau interne', 'threat-report', 'no-vocabulary']);
    // The vocabularies of the category of the field, matched by the engine on the indexed form of their name
    expect(engine.elKeywordWrittenForms).toHaveBeenCalledTimes(1);
    const [, vocabularyUser, vocabularyIndices, vocabularyOptions] = vi.mocked(engine.elKeywordWrittenForms).mock.calls[0];
    expect(vocabularyUser).toBe(accessModule.SYSTEM_USER);
    expect(vocabularyIndices).toEqual(READ_INDEX_STIX_META_OBJECTS);
    expect(vocabularyOptions).toEqual({
      types: ['Vocabulary'],
      filters: { mode: 'and', filters: [{ key: ['category'], values: ['report_types_ov'] }], filterGroups: [] },
      noFiltersChecking: true,
      field: 'name',
      keys: ['reseau interne', 'threat-report', 'no-vocabulary'],
    });
  });

  it('should name the vocabulary values as the engine matched them, whatever their letters', async () => {
    // No folding on this side: the indexed forms are the engine's, of the field as of the names of the vocabularies
    const writtenForms = new Map([['высокий', 'Высокий'], ['strasse', 'Straße'], ['ħ ŋ ĳ ſ ﬁ ｆｕｌｌ', 'Ħ Ŋ Ĳ ſ ﬁ ＦＵＬＬ']]);
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([...writtenForms.keys()].map((key, i) => bucket(key, 3 - i))));
    vi.mocked(engine.elKeywordWrittenForms).mockResolvedValue(writtenForms);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'report_types' });

    expect(result.series.map((serie) => serie.label)).toEqual([...writtenForms.values()]);
  });

  it('should name the enum values as they are written in the schema, without reading anything', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('critical', 4), bucket('unknown', 2), bucket('not-in-schema', 1)]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'x_opencti_cvss_base_severity' });

    expect(result.series.map((serie) => serie.label)).toEqual(['CRITICAL', 'Unknown', 'not-in-schema']);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['critical', 'unknown', 'not-in-schema']);
    expect(engine.elKeywordWrittenForms).not.toHaveBeenCalled();
  });

  it('should name the entity types after their registered type, without entity', async () => {
    // The labels converted from the indexed type garble some of them
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([
      { key: 'intrusion-set', label: 'Intrusion-Set', value: 6, count: 6 },
      { key: 'malware', label: 'Malware', value: 4, count: 4 },
      { key: 'imei', label: 'Imei', value: 3, count: 3 },
      { key: 'securityplatform', label: 'Securityplatform', value: 2, count: 2 },
      { key: 'not-registered', label: 'Not-Registered', value: 1, count: 1 },
    ]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'entity_type' });

    expect(engine.elFindByIds).not.toHaveBeenCalled();
    expect(result.series.map((serie) => serie.label)).toEqual(['Intrusion-Set', 'Malware', 'IMEI', 'SecurityPlatform', 'not-registered']);
    expect(result.series.every((serie) => serie.entity === null)).toBe(true);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['intrusion-set', 'malware', 'imei', 'securityplatform', 'not-registered']);
  });

  it('should restrict the authors the user cannot access, and keep their entities counted', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('identity-a', 5), bucket('identity-b', 3)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'identity-a': { ...makeEntity('identity-a', 'Filigran'), entity_type: 'Organization' },
      'identity-b': { ...makeEntity('identity-b', 'Secret'), entity_type: 'Organization' },
    } as any);
    vi.mocked(accessModule.userFilterStoreElements).mockImplementation(async (_context, _user, elements) => elements.filter((element) => element.internal_id === 'identity-a'));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf([['identity-b', [{ date: '2026-01-02', value: 3 }]]]));

    const result = await breakdown({ field: 'createdBy' });

    expect((vi.mocked(engine.elAggregationRanking).mock.calls[0][3] as any).field).toEqual('rel_created-by.internal_id');
    // The restricted author keeps its series, under its id and without any of its attributes
    expect(result.series.map((serie) => [serie.label, (serie.entity as any)?.name, (serie.entity as any)?.entity_type])).toEqual([
      ['identity-a', 'Filigran', 'Organization'],
      ['identity-b', 'Restricted', 'Organization'],
    ]);
    expect(result.series[1]).toMatchObject({ total: 3, values: [0, 3, 0] });
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['identity-a', 'identity-b']);
  });

  it('should query both aggregations with the same filters, field and inclusive bounds', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('label-a', 4)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'label-a': makeEntity('label-a', 'tlp') } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());
    const filters = { mode: 'and', filters: [{ key: ['confidence'], values: ['50'], operator: 'gt' }], filterGroups: [] };

    await breakdown({ field: 'objectLabel', dateAttribute: 'published', filters });

    const discoveryOptions = vi.mocked(engine.elAggregationRanking).mock.calls[0][3] as any;
    const histogramOptions = vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3] as any;
    for (const options of [discoveryOptions, histogramOptions]) {
      expect(options.field).toEqual('rel_object-label.internal_id');
      expect(options.dateAttribute).toEqual('published');
      expect(options.intervalInclude).toBe(true);
      expect(options.startDate).toEqual(startDate);
      expect(options.endDate).toEqual(endDate);
      expect(options.filters).toEqual(filters);
    }
  });

  it('should skip the histogram query when no value is found, and still give the dates of the period', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([]));

    const result = await breakdown({ field: 'creator_id' });

    expect(result).toEqual({
      truncated: false,
      dates: ['2026-01-01T00:00:00.000Z', '2026-01-02T00:00:00.000Z', '2026-01-03T00:00:00.000Z'],
      series: [],
    });
    expect(engine.elHistogramBreakdownCount).not.toHaveBeenCalled();
  });

  it('should not read the vocabularies when only the Other series is counted', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await breakdown({ field: 'report_types', includeOther: true });

    expect(result.series.map((serie) => serie.isOther)).toEqual([true]);
    expect(engine.elKeywordWrittenForms).not.toHaveBeenCalled();
  });
});

describe('BREAKDOWN_REFUSAL_REASONS', () => {
  it('should keep the reasons the front tells the refusals apart from', () => {
    expect(BREAKDOWN_REFUSAL_REASONS).toEqual({
      INVALID_LIMIT: 'invalid_limit',
      UNSUPPORTED_FIELD: 'unsupported_field',
      UNSUPPORTED_DATE_ATTRIBUTE: 'unsupported_date_attribute',
      TOO_LARGE: 'too_large',
      TOO_MANY_VALUES: 'too_many_values',
    });
  });
});

describe('checkBreakdownDateAttribute', () => {
  beforeEach(() => {
    // The registered schema
    vi.restoreAllMocks();
  });

  const refusal = (dateAttribute: string, types: string[]) => ({
    extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'unsupported_date_attribute', dateAttribute, types } },
  });

  it('should accept the date attributes of the types', () => {
    expect(() => checkBreakdownDateAttribute(['Report'], 'published')).not.toThrow();
    expect(() => checkBreakdownDateAttribute(['Report'], 'created_at')).not.toThrow();
    expect(() => checkBreakdownDateAttribute(['Report', 'Malware'], 'first_seen')).not.toThrow();
    expect(() => checkBreakdownDateAttribute(['History', 'Activity'], 'timestamp')).not.toThrow();
    expect(() => checkBreakdownDateAttribute(['uses'], 'start_time')).not.toThrow();
    expect(() => checkBreakdownDateAttribute(['stix-sighting-relationship'], 'last_seen')).not.toThrow();
  });

  it('should accept the date attributes of the types an abstract type stands for', () => {
    // The default types of the entities and of the relationships
    expect(() => checkBreakdownDateAttribute(['Stix-Core-Object'], 'first_seen')).not.toThrow();
    expect(() => checkBreakdownDateAttribute(['Stix-Core-Object'], 'published')).not.toThrow();
    expect(() => checkBreakdownDateAttribute(['stix-relationship'], 'start_time')).not.toThrow();
    expect(() => checkBreakdownDateAttribute(['stix-relationship'], 'first_seen')).not.toThrow();
  });

  it('should refuse any field that is not a date attribute of the types', () => {
    const cases: [string, string[]][] = [
      ['name', ['Report']],
      ['description', ['Report']],
      ['confidence', ['Report']],
      ['report_types', ['Report']],
      ['objectLabel', ['Report']],
      ['rel_object-marking.internal_id', ['Report']],
      ['not_an_attribute', ['Stix-Core-Object']],
      // A date of other types only
      ['first_seen', ['Report']],
      ['published', ['uses']],
      ['start_time', ['stix-sighting-relationship']],
      ['event_type', ['History', 'Activity']],
      ['context_data.entity_type', ['History']],
      ['first_seen', ['History']],
      ['created_at', ['Not-A-Type']],
    ];
    cases.forEach(([dateAttribute, types]) => {
      let error: unknown;
      try {
        checkBreakdownDateAttribute(types, dateAttribute);
      } catch (e) {
        error = e;
      }
      expect(error, dateAttribute).toMatchObject(refusal(dateAttribute, types));
    });
  });
});

describe('resolveBreakdownField', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSchema();
    mockRegisteredTypes();
  });

  it('should aggregate relation refs on their denormalized ids and resolve their entities', () => {
    expect(resolveBreakdownField(['Report'], 'createdBy')).toEqual({ aggregationField: 'rel_created-by.internal_id', resolveEntities: true });
  });

  it('should aggregate id, vocabulary and enum attributes as they are', () => {
    expect(resolveBreakdownField(['Report'], 'creator_id')).toEqual({ aggregationField: 'creator_id', resolveEntities: true, withInternalUsers: true });
    expect(resolveBreakdownField(['Report'], 'report_types')).toEqual({ aggregationField: 'report_types', resolveEntities: false, vocabularyCategories: ['report_types_ov'] });
    expect(resolveBreakdownField(['Report'], 'x_opencti_cvss_base_severity')).toMatchObject({ aggregationField: 'x_opencti_cvss_base_severity', resolveEntities: false });
    expect(resolveBreakdownField(['Report', 'Malware'], 'entity_type')).toMatchObject({ aggregationField: 'entity_type', resolveEntities: false });
  });

  it('should name the entity types after their registered type', () => {
    const { resolveLabel } = resolveBreakdownField(['Stix-Cyber-Observable', 'Identity'], 'entity_type');
    expect(['imei', 'securityplatform', 'intrusion-set', 'not-registered'].map((key) => resolveLabel?.(key))).toEqual(['IMEI', 'SecurityPlatform', 'Intrusion-Set', 'not-registered']);
  });

  it('should accept creator_id as the only id attribute', () => {
    expect(resolveBreakdownField(['Report'], 'creator_id').aggregationField).toEqual('creator_id');
    expect(() => resolveBreakdownField(['Report'], 'pir_ids')).toThrow('does not support this field');
  });

  it('should refuse relation refs outside the allowlist', () => {
    expect(BREAKDOWN_ALLOWED_REFS).toEqual(['createdBy', 'objectLabel', 'objectMarking', 'objectAssignee', 'objectParticipant']);
    expect(() => resolveBreakdownField(['Report'], 'objects')).toThrow('does not support this field');
    expect(() => resolveBreakdownField(['Report'], 'externalReferences')).toThrow('does not support this field');
    expect(() => resolveBreakdownField(['Report'], 'killChainPhases')).toThrow('does not support this field');
  });

  it('should only accept a field carried by every requested type', () => {
    expect(resolveBreakdownField(['Report', 'Malware'], 'objectLabel').resolveEntities).toBe(true);
    expect(() => resolveBreakdownField(['Report', 'Malware'], 'report_types')).toThrow('does not support this field');
  });
});

describe('normalizeEnumValue', () => {
  it('should give the indexed form of the enum values', () => {
    expect(['CRITICAL', 'Unknown', 'THREAT_CUSTOM', 'not-in-schema'].map(normalizeEnumValue)).toEqual(['critical', 'unknown', 'threat_custom', 'not-in-schema']);
  });

  it('should only meet ASCII enum values, which the keyword normalizer only lowercases', () => {
    vi.restoreAllMocks();
    const enumValues = schemaAttributesDefinition.getAllAttributes()
      .flatMap((attribute) => (attribute.type === 'string' && attribute.format === 'enum' ? attribute.values : []));
    expect(enumValues.length).toBeGreaterThan(0);
    // eslint-disable-next-line no-control-regex
    expect(enumValues.filter((value) => !/^[\x00-\x7f]*$/.test(value))).toEqual([]);
  });
});

describe('resolveHistoryBreakdownField', () => {
  it('should accept the event, author and type fields of the logs as they are indexed', () => {
    expect(HISTORY_BREAKDOWN_ALLOWED_FIELDS).toEqual([
      'event_type',
      'event_scope',
      'user_id',
      'group_ids',
      'organization_ids',
      'entity_type',
      'context_data.entity_type',
    ]);
    HISTORY_BREAKDOWN_ALLOWED_FIELDS.forEach((field) => {
      expect(resolveHistoryBreakdownField(field).aggregationField).toEqual(field);
    });
  });

  it('should resolve the users, groups and organizations, and only them', () => {
    const resolved = HISTORY_BREAKDOWN_ALLOWED_FIELDS.filter((field) => resolveHistoryBreakdownField(field).resolveEntities);
    expect(resolved).toEqual(['user_id', 'group_ids', 'organization_ids']);
    // Only the users can be internal users
    expect(HISTORY_BREAKDOWN_ALLOWED_FIELDS.filter((field) => resolveHistoryBreakdownField(field).withInternalUsers)).toEqual(['user_id']);
  });

  it('should refuse the fields with an unbounded cardinality, free texts and unknown fields', () => {
    [
      'context_data.id',
      'context_data.entity_id',
      'context_data.entity_name',
      'context_data.message',
      'context_data.search',
      'context_data.filters',
      'applicant_id',
      'timestamp',
      'internal_id',
      'creator_id',
      'createdBy',
      'constructor',
      '__proto__',
      '',
    ].forEach((field) => {
      expect(() => resolveHistoryBreakdownField(field)).toThrow('does not support this field for the history and activity logs');
    });
  });
});

describe('timeSeriesBreakdownHistory', () => {
  const historyBreakdown = (args: Record<string, unknown>) => timeSeriesBreakdownHistory(mockContext, accessModule.SYSTEM_USER, {
    startDate,
    endDate,
    interval: 'day',
    types: ['History', 'Activity'],
    historyFiltering: true,
    ...args,
  } as any);

  beforeEach(() => {
    vi.clearAllMocks();
    // The registered attributes of the logs
    vi.restoreAllMocks();
    vi.spyOn(accessModule, 'userFilterStoreElements').mockImplementation(async (_context, _user, elements) => elements);
    mockRegisteredTypes();
  });

  it('should refuse a field outside the allowlist before querying', async () => {
    await expect(historyBreakdown({ field: 'context_data.id' })).rejects.toThrow('does not support this field');
    await expect(historyBreakdown({ field: 'context_data.message' })).rejects.toMatchObject({
      extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'unsupported_field', field: 'context_data.message' } },
    });
    expect(engine.elAggregationRanking).not.toHaveBeenCalled();
  });

  it('should check the limit and the size of the breakdown like the entities', async () => {
    await expect(historyBreakdown({ field: 'event_scope', limit: 51 })).rejects.toThrow('Time series breakdown limit');
    const threeYearsLater = new Date('2029-01-01T12:00:00.000Z');
    await expect(historyBreakdown({ field: 'event_scope', limit: 50, endDate: threeYearsLater })).rejects.toThrow('too large');
    expect(engine.elAggregationRanking).not.toHaveBeenCalled();
  });

  it('should query the logs index with the types, filters and history filtering of the caller, on the timestamp', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('create', 4)]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());
    const filters = { mode: 'and', filters: [{ key: ['event_type'], values: ['mutation'], operator: 'eq' }], filterGroups: [] };

    await historyBreakdown({ field: 'event_scope', filters, search: 'report' });

    const [, , discoveryIndices, discoveryOptions] = vi.mocked(engine.elAggregationRanking).mock.calls[0] as any[];
    const [, , histogramIndices, histogramOptions] = vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0] as any[];
    expect(discoveryIndices).toEqual(READ_INDEX_HISTORY);
    expect(histogramIndices).toEqual(READ_INDEX_HISTORY);
    for (const options of [discoveryOptions, histogramOptions]) {
      expect(options.field).toEqual('event_scope');
      expect(options.types).toEqual(['History', 'Activity']);
      expect(options.historyFiltering).toBe(true);
      expect(options.filters).toEqual(filters);
      expect(options.search).toEqual('report');
      expect(options.dateAttribute).toEqual('timestamp');
      expect(options.intervalInclude).toBe(true);
      expect(options.startDate).toEqual(startDate);
      expect(options.endDate).toEqual(endDate);
    }
  });

  it('should always filter the history, whatever the caller', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('create', 4)]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    await historyBreakdown({ field: 'event_scope', historyFiltering: undefined, types: undefined });

    for (const call of [vi.mocked(engine.elAggregationRanking).mock.calls[0], vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0]]) {
      const options = call[3] as any;
      expect(options.historyFiltering).toBe(true);
      // Without types, only the history, like the other logs aggregations
      expect(options.types).toEqual(['History']);
    }
  });

  it('should refuse a date attribute that is not a date of the logs, whatever the types requested', async () => {
    for (const [dateAttribute, types] of [['event_type', ['History']], ['context_data.message', ['Activity']], ['published', ['Report']]]) {
      await expect(historyBreakdown({ field: 'event_scope', dateAttribute, types })).rejects.toMatchObject({
        extensions: { data: { reason: 'unsupported_date_attribute', dateAttribute, types: ['History', 'Activity'] } },
      });
    }
    expect(engine.elAggregationRanking).not.toHaveBeenCalled();
  });

  it('should keep a date attribute given by the widget, and end the period now without end date', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('create', 4)]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());
    const recentStartDate = new Date(Date.now() - 2 * 86400000);

    const before = Date.now();
    const result = await historyBreakdown({ field: 'event_scope', dateAttribute: 'created_at', startDate: recentStartDate, endDate: undefined });

    const histogramOptions = vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3] as any;
    expect(histogramOptions.dateAttribute).toEqual('created_at');
    expect(histogramOptions.endDate.getTime()).toBeGreaterThanOrEqual(before);
    expect(result.dates).toHaveLength(3);
  });

  it('should keep the raw values of the event fields, without entity, ranked on their number of events', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('update', 2), bucket('create', 6)]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf([['create', [{ date: '2026-01-02', value: 6 }]]]));

    const result = await historyBreakdown({ field: 'event_scope', orderMode: 'desc' });

    expect(vi.mocked(engine.elAggregationRanking).mock.calls[0][3]).toMatchObject({ rankingOrder: 'desc' });
    expect(engine.elFindByIds).not.toHaveBeenCalled();
    expect(result.series.map((serie) => serie.label)).toEqual(['create', 'update']);
    expect(result.series.every((serie) => serie.entity === null)).toBe(true);
    expect(result.series[0]).toMatchObject({ total: 6, values: [0, 6, 0] });
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['create', 'update']);
  });

  it('should keep the SYSTEM user as a creator and drop the deleted users before applying the limit', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([
      bucket(accessModule.SYSTEM_USER.id, 50),
      bucket('user-a', 10),
      bucket('deleted-user', 8),
      bucket('user-b', 5),
      bucket('user-c', 3),
    ]));
    // Neither the SYSTEM user nor a deleted user is stored
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'user-a': makeEntity('user-a', 'Alice'),
      'user-b': makeEntity('user-b', 'Bob'),
      'user-c': makeEntity('user-c', 'Carol'),
    } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await historyBreakdown({ field: 'user_id', limit: 3 });

    expect(result.truncated).toBe(true);
    expect(result.series.map((serie) => (serie.entity as any)?.name)).toEqual(['SYSTEM', 'Alice', 'Bob']);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual([accessModule.SYSTEM_USER.id, 'user-a', 'user-b']);
    // The SYSTEM user is not looked for in the indices
    expect(vi.mocked(engine.elFindByIds).mock.calls[0][2]).toEqual(['user-a', 'deleted-user', 'user-b', 'user-c']);
  });

  it('should not take the internal users for groups or organizations', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket(accessModule.SYSTEM_USER.id, 5), bucket('org-a', 3)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'org-a': { ...makeEntity('org-a', 'Filigran'), entity_type: 'Organization' } } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await historyBreakdown({ field: 'organization_ids' });

    expect(result.series.map((serie) => serie.label)).toEqual(['org-a']);
  });

  it('should restrict the users, groups and organizations the user cannot access', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('org-a', 10), bucket('org-b', 5)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'org-a': { ...makeEntity('org-a', 'Filigran'), entity_type: 'Organization' },
      'org-b': { ...makeEntity('org-b', 'Hidden'), entity_type: 'Organization' },
    } as any);
    vi.mocked(accessModule.userFilterStoreElements).mockImplementation(async (_context, _user, elements) => elements.filter((element) => element.id === 'org-a'));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await historyBreakdown({ field: 'organization_ids' });

    expect(result.series.map((serie) => (serie.entity as any)?.name)).toEqual(['Filigran', 'Restricted']);
    expect(result.series[1].label).toEqual('org-b');
  });

  it('should name the indexed entity types after their registered type', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([
      bucket('report', 6),
      bucket('intrusion-set', 4),
      bucket('publicdashboard', 3),
      bucket('uses', 2),
      bucket('not-registered', 1),
    ]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await historyBreakdown({ field: 'context_data.entity_type' });

    expect(result.series.map((serie) => serie.label)).toEqual(['Report', 'Intrusion-Set', 'PublicDashboard', 'uses', 'not-registered']);
    // The histogram still targets the values as indexed
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['report', 'intrusion-set', 'publicdashboard', 'uses', 'not-registered']);

    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('history', 6), bucket('activity', 4)]));
    const byLogType = await historyBreakdown({ field: 'entity_type' });
    expect(byLogType.series.map((serie) => serie.label)).toEqual(['History', 'Activity']);
  });

  it('should add the Other series of the events with none of the displayed values', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('create', 6), bucket('update', 2)]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf([], [{ date: '2026-01-01', value: 3 }]));

    const result = await historyBreakdown({ field: 'event_scope', limit: 1, includeOther: true });

    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3]).toMatchObject({ keys: ['create'], withOther: true });
    expect(result.series.map((serie) => serie.label)).toEqual(['create', 'Other']);
    expect(result.series[1]).toMatchObject({ isOther: true, total: 3, values: [3, 0, 0] });
  });
});

// Minimal relationship schema: every relationship type carries an author, labels, markings, kill chain phases,
// external references and creators. Uses alone has a vocabulary.
const RELATIONSHIP_REFS: Record<string, string> = {
  createdBy: 'created-by',
  objectLabel: 'object-label',
  objectMarking: 'object-marking',
  killChainPhases: 'kill-chain-phase',
  externalReferences: 'external-reference',
};
const RELATIONSHIP_ATTRIBUTES: Record<string, { type: string; format?: string; vocabularyCategory?: string }> = {
  creator_id: { type: 'string', format: 'id' },
  relationship_type: { type: 'string', format: 'short' },
  entity_type: { type: 'string', format: 'short' },
  description: { type: 'string', format: 'text' },
  confidence: { type: 'numeric' },
  start_time: { type: 'date' },
  usage_types: { type: 'string', format: 'vocabulary', vocabularyCategory: 'usage_types_ov' },
};
const mockRelationshipSchema = () => {
  vi.spyOn(schemaRelationsRefDefinition, 'getRelationRef').mockImplementation((_type, name) => (
    name && RELATIONSHIP_REFS[name] ? { name, databaseName: RELATIONSHIP_REFS[name] } as any : null
  ));
  vi.spyOn(schemaAttributesDefinition, 'getAttribute').mockImplementation((type, name) => {
    if (name === 'usage_types' && type !== 'uses') return undefined;
    return RELATIONSHIP_ATTRIBUTES[name] ? { name, isFilterable: true, ...RELATIONSHIP_ATTRIBUTES[name] } as any : undefined;
  });
};

describe('resolveRelationshipBreakdownField', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRelationshipSchema();
    mockRegisteredTypes();
  });

  it('should break relationships down by their type, as indexed', () => {
    expect(resolveRelationshipBreakdownField(['stix-relationship'], 'relationship_type')).toEqual({
      aggregationField: 'relationship_type',
      resolveEntities: false,
    });
  });

  it('should break relationships down by the type of their source or of their target', () => {
    const fromTypes = resolveRelationshipBreakdownField(['uses'], 'fromTypes');
    const toTypes = resolveRelationshipBreakdownField(['uses'], 'toTypes');
    expect(fromTypes).toMatchObject({ aggregationField: 'connections.types', resolveEntities: false, connectionSide: 'from' });
    expect(toTypes).toMatchObject({ aggregationField: 'connections.types', resolveEntities: false, connectionSide: 'to' });
    // Named after their registered type by the engine, which ranks them: never named again
    expect(fromTypes.resolveLabel).toBeUndefined();
    expect(toTypes.resolveLabel).toBeUndefined();
  });

  it('should accept the author, labels, markings and creators of the relationships', () => {
    const types = ['uses', 'targets'];
    expect(resolveRelationshipBreakdownField(types, 'createdBy')).toEqual({ aggregationField: 'rel_created-by.internal_id', resolveEntities: true });
    expect(resolveRelationshipBreakdownField(types, 'objectLabel')).toEqual({ aggregationField: 'rel_object-label.internal_id', resolveEntities: true });
    expect(resolveRelationshipBreakdownField(types, 'objectMarking')).toEqual({ aggregationField: 'rel_object-marking.internal_id', resolveEntities: true });
    expect(resolveRelationshipBreakdownField(types, 'creator_id')).toEqual({ aggregationField: 'creator_id', resolveEntities: true, withInternalUsers: true });
  });

  it('should refuse the source and target themselves, and the fields that cannot be broken down', () => {
    // fromId, toId and objects have an unbounded cardinality; entity_type is the relationship type itself
    ['fromId', 'toId', 'objects', 'externalReferences', 'killChainPhases', 'entity_type', 'description', 'confidence', 'start_time', 'regardingOf', 'constructor']
      .forEach((field) => {
        expect(() => resolveRelationshipBreakdownField(['uses'], field)).toThrow('does not support this field for these relationship types');
      });
  });

  it('should only accept a vocabulary carried by every requested relationship type', () => {
    expect(resolveRelationshipBreakdownField(['uses'], 'usage_types')).toEqual({ aggregationField: 'usage_types', resolveEntities: false, vocabularyCategories: ['usage_types_ov'] });
    expect(() => resolveRelationshipBreakdownField(['uses', 'targets'], 'usage_types')).toThrow('does not support this field');
  });

  it('should keep the relationships fields out of the entities breakdown', () => {
    mockSchema();
    ['relationship_type', 'fromTypes', 'toTypes'].forEach((field) => {
      expect(() => resolveBreakdownField(['Report'], field)).toThrow('does not support this field for these entity types');
    });
  });
});

const relationsBreakdown = (args: Record<string, unknown>, relationshipTypes = ['uses', 'targets']) => timeSeriesBreakdownRelations(
  mockContext,
  accessModule.SYSTEM_USER,
  relationshipTypes,
  { startDate, endDate, interval: 'day', ...args } as any,
);

describe('timeSeriesBreakdownRelations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(accessModule, 'userFilterStoreElements').mockImplementation(async (_context, _user, elements) => elements);
    mockRelationshipSchema();
    mockRegisteredTypes();
  });

  it('should refuse a date attribute that is not a date of the relationship types', async () => {
    for (const dateAttribute of ['description', 'relationship_type', 'confidence']) {
      await expect(relationsBreakdown({ field: 'relationship_type', dateAttribute })).rejects.toMatchObject({
        extensions: { data: { reason: 'unsupported_date_attribute', dateAttribute, types: ['uses', 'targets'] } },
      });
    }
    expect(engine.elAggregationRanking).not.toHaveBeenCalled();
    expect(engine.elConnectionTypesRanking).not.toHaveBeenCalled();
  });

  it('should reject a limit out of bounds and the fields that cannot be broken down', async () => {
    await expect(relationsBreakdown({ field: 'relationship_type', limit: 0 })).rejects.toThrow('Time series breakdown limit');
    await expect(relationsBreakdown({ field: 'relationship_type', limit: 51 })).rejects.toThrow('Time series breakdown limit');
    await expect(relationsBreakdown({ field: 'fromId' })).rejects.toThrow('does not support this field for these relationship types');
    await expect(relationsBreakdown({ field: 'fromId' })).rejects.toMatchObject({
      extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'unsupported_field', field: 'fromId', types: ['uses', 'targets'] } },
    });
    await expect(relationsBreakdown({ field: 'relationship_type', limit: 51 })).rejects.toMatchObject({ extensions: { data: { reason: 'invalid_limit' } } });
    expect(engine.elAggregationRanking).not.toHaveBeenCalled();
    expect(engine.elConnectionTypesRanking).not.toHaveBeenCalled();
  });

  it('should count the relationships of the requested types in the relationships indices', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('uses', 5)]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());
    const filters = { mode: 'and', filters: [{ key: ['confidence'], values: ['50'], operator: 'gt' }], filterGroups: [] };

    await relationsBreakdown({ field: 'relationship_type', dateAttribute: 'start_time', filters });

    const [, , discoveryIndices, discoveryOptions] = vi.mocked(engine.elAggregationRanking).mock.calls[0] as any[];
    const [, , histogramIndices, histogramOptions] = vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0] as any[];
    expect(discoveryIndices).toEqual(READ_RELATIONSHIPS_INDICES);
    expect(histogramIndices).toEqual(READ_RELATIONSHIPS_INDICES);
    for (const options of [discoveryOptions, histogramOptions]) {
      expect(options.types).toEqual(['uses', 'targets']);
      expect(options.field).toEqual('relationship_type');
      expect(options.dateAttribute).toEqual('start_time');
      expect(options.intervalInclude).toBe(true);
      expect(options.filters).toEqual(filters);
    }

    await relationsBreakdown({ field: 'relationship_type', onlyInferred: true });
    expect(vi.mocked(engine.elAggregationRanking).mock.lastCall?.[2]).toEqual(INDEX_INFERRED_RELATIONSHIPS);
  });

  it('should keep the relationship type as label, without entity', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('uses', 5), bucket('targets', 3)]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf([
      ['uses', [{ date: '2026-01-02', value: 5 }]],
      ['targets', [{ date: '2026-01-01', value: 1 }, { date: '2026-01-03', value: 2 }]],
    ]));

    const result = await relationsBreakdown({ field: 'relationship_type' });

    expect(engine.elFindByIds).not.toHaveBeenCalled();
    expect(engine.elConnectionTypesRanking).not.toHaveBeenCalled();
    // Ranked on their number of relationships, like the fields of the entities
    expect(vi.mocked(engine.elAggregationRanking).mock.calls[0][3]).toMatchObject({ field: 'relationship_type', rankingOrder: 'desc' });
    expect(result.series.map((serie) => [serie.label, serie.total, serie.entity])).toEqual([['uses', 5, null], ['targets', 3, null]]);
    expect(result.series.map((serie) => serie.values)).toEqual([[0, 5, 0], [1, 0, 2]]);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].connectionSide).toBeUndefined();
  });

  it('should break down by the type of the source through the connections of the relationships', async () => {
    vi.mocked(engine.elConnectionTypesRanking).mockResolvedValue(ranking([
      { key: 'malware', label: 'Malware', value: 4, count: 4 },
      { key: 'intrusion-set', label: 'Intrusion-Set', value: 2, count: 2 },
    ]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf([['malware', [{ date: '2026-01-01', value: 4 }]]], [{ date: '2026-01-03', value: 1 }]));

    const result = await relationsBreakdown({ field: 'fromTypes', includeOther: true });

    expect(engine.elAggregationRanking).not.toHaveBeenCalled();
    const discoveryOptions = vi.mocked(engine.elConnectionTypesRanking).mock.calls[0][3];
    expect(discoveryOptions).toMatchObject({ connectionSide: 'from', rankingOrder: 'desc', types: ['uses', 'targets'], intervalInclude: true });
    const histogramOptions = vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3];
    expect(histogramOptions).toMatchObject({ connectionSide: 'from', keys: ['malware', 'intrusion-set'], withOther: true });
    expect(result.series.map((serie) => [serie.label, serie.total, serie.entity, serie.isOther])).toEqual([
      ['Malware', 4, null, false],
      // The value of a series is the sum of its values: no histogram bucket, no relationship
      ['Intrusion-Set', 0, null, false],
      ['Other', 1, null, true],
    ]);
    expect(result.series[2].values).toEqual([0, 0, 1]);
  });

  it('should break down by the type of the target, lowest values first in asc order', async () => {
    vi.mocked(engine.elConnectionTypesRanking).mockResolvedValue(ranking([
      { key: 'sector', label: 'Sector', value: 6, count: 6 },
      { key: 'country', label: 'Country', value: 1, count: 1 },
    ]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await relationsBreakdown({ field: 'toTypes', orderMode: 'asc', limit: 1 });

    expect(vi.mocked(engine.elConnectionTypesRanking).mock.calls[0][3]).toMatchObject({ connectionSide: 'to', rankingOrder: 'asc' });
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3]).toMatchObject({ connectionSide: 'to', keys: ['country'] });
    expect(result.truncated).toBe(true);
    expect(result.series.map((serie) => serie.label)).toEqual(['Country']);
  });

  it('should keep the names the engine gives the types of a side', async () => {
    vi.mocked(engine.elConnectionTypesRanking).mockResolvedValue(ranking([
      { key: 'imei', label: 'IMEI', value: 3, count: 3 },
      { key: 'securityplatform', label: 'SecurityPlatform', value: 2, count: 2 },
    ]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await relationsBreakdown({ field: 'toTypes' });

    expect(result.series.map((serie) => serie.label)).toEqual(['IMEI', 'SecurityPlatform']);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['imei', 'securityplatform']);
  });

  it('should pass the refusal of the lowest types of a side on to the caller', async () => {
    vi.mocked(engine.elConnectionTypesRanking).mockRejectedValue(tooManyValuesError());

    await expect(relationsBreakdown({ field: 'fromTypes', orderMode: 'asc' })).rejects.toMatchObject({
      extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'too_many_values', max: engine.MAX_EXACT_RANKING_SIZE } },
    });
    expect(engine.elHistogramBreakdownCount).not.toHaveBeenCalled();
  });

  it('should resolve the authors of the relationships, restricted ones included', async () => {
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('identity-a', 3), bucket('identity-b', 2)]));
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'identity-a': makeEntity('identity-a', 'Filigran'),
      'identity-b': makeEntity('identity-b', 'Secret'),
    } as any);
    vi.mocked(accessModule.userFilterStoreElements).mockImplementation(async (_context, _user, elements) => elements.filter((element) => element.internal_id === 'identity-a'));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    const result = await relationsBreakdown({ field: 'createdBy' });

    expect((vi.mocked(engine.elAggregationRanking).mock.calls[0][3] as any).field).toEqual('rel_created-by.internal_id');
    expect(result.series.map((serie) => (serie.entity as any)?.name)).toEqual(['Filigran', 'Restricted']);
  });

  it('should count the Other series in the maximum number of buckets and end the period now', async () => {
    const thousandDaysLater = new Date('2028-09-26T12:00:00.000Z');
    await expect(relationsBreakdown({ field: 'relationship_type', limit: 50, endDate: thousandDaysLater, includeOther: true })).rejects.toThrow('too large');
    expect(engine.elAggregationRanking).not.toHaveBeenCalled();

    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('uses', 1)]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());
    const before = Date.now();
    const result = await relationsBreakdown({ field: 'relationship_type', startDate: new Date(Date.now() - 2 * 86400000), endDate: undefined });
    const histogramOptions = vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3] as any;
    expect(histogramOptions.endDate.getTime()).toBeGreaterThanOrEqual(before);
    expect(result.dates).toHaveLength(3);
  });

  it('should reject an unsupported interval before querying', async () => {
    await expect(relationsBreakdown({ field: 'fromTypes', interval: 'minute' })).rejects.toThrow('Unsupported interval');
    expect(engine.elConnectionTypesRanking).not.toHaveBeenCalled();
  });

  it('should not break the entities down through the connections', async () => {
    mockSchema();
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('report', 1)]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());

    await breakdown({ field: 'entity_type' });

    expect(engine.elConnectionTypesRanking).not.toHaveBeenCalled();
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].connectionSide).toBeUndefined();
  });
});

describe('stixRelationshipsTimeSeriesBreakdown', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRelationshipSchema();
    vi.mocked(engine.elAggregationRanking).mockResolvedValue(ranking([bucket('targets', 4)]));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(histogramsOf());
    vi.mocked(engine.elHistogramCount).mockResolvedValue([]);
  });

  const filters = { mode: 'and', filters: [{ key: ['relationship_type'], values: ['targets'], operator: 'eq', mode: 'or' }], filterGroups: [] };
  const dynamicFrom = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Malware'], operator: 'eq', mode: 'or' }], filterGroups: [] };
  const dynamicTo = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Sector'], operator: 'eq', mode: 'or' }], filterGroups: [] };

  it('should restrict the relationships exactly as the relationships time series does', async () => {
    const timeSeries = await stixRelationshipsMultiTimeSeries(mockContext, accessModule.SYSTEM_USER, {
      operation: 'count',
      startDate,
      endDate,
      interval: 'day',
      timeSeriesParameters: [{ field: 'start_time', filters, dynamicFrom, dynamicTo }],
    });
    await Promise.all(timeSeries.map((serie) => serie.data));
    const timeSeriesOptions = vi.mocked(engine.elHistogramCount).mock.calls[0][3] as any;

    await stixRelationshipsTimeSeriesBreakdown(mockContext, accessModule.SYSTEM_USER, {
      field: 'relationship_type',
      dateAttribute: 'start_time',
      startDate,
      endDate,
      interval: 'day',
      filters,
      dynamicFrom,
      dynamicTo,
    });
    const discoveryOptions = vi.mocked(engine.elAggregationRanking).mock.calls[0][3] as any;
    const histogramOptions = vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3] as any;

    // The dynamic source and target are applied as filters, on all the relationships without relationship type
    expect(JSON.stringify(timeSeriesOptions.filters)).toContain('dynamicFrom');
    expect(JSON.stringify(timeSeriesOptions.filters)).toContain('dynamicTo');
    for (const options of [discoveryOptions, histogramOptions]) {
      expect(options.filters).toEqual(timeSeriesOptions.filters);
      expect(options.types).toEqual(timeSeriesOptions.types);
      expect(options.types).toEqual(['stix-relationship']);
      expect(options.dateAttribute).toEqual(timeSeriesOptions.field);
    }
  });

  it('should check the field against the requested relationship types', async () => {
    await stixRelationshipsTimeSeriesBreakdown(mockContext, accessModule.SYSTEM_USER, {
      field: 'usage_types', startDate, endDate, interval: 'day', relationship_type: ['uses'],
    });
    expect((vi.mocked(engine.elAggregationRanking).mock.calls[0][3] as any).types).toEqual(['uses']);
    await expect(stixRelationshipsTimeSeriesBreakdown(mockContext, accessModule.SYSTEM_USER, {
      field: 'usage_types', startDate, endDate, interval: 'day', relationship_type: ['uses', 'targets'],
    })).rejects.toThrow('does not support this field');
  });

  it('should refuse relationship types that are not relationships', async () => {
    await expect(stixRelationshipsTimeSeriesBreakdown(mockContext, accessModule.SYSTEM_USER, {
      field: 'relationship_type', startDate, endDate, interval: 'day', relationship_type: ['Malware'],
    })).rejects.toThrow('relationship_type is not a stix-relationship');
  });
});
