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
import {
  BREAKDOWN_ALLOWED_REFS,
  distributionEntities,
  distributionHistory,
  HISTORY_BREAKDOWN_ALLOWED_FIELDS,
  resolveBreakdownField,
  resolveHistoryBreakdownField,
  resolveRelationshipBreakdownField,
  timeSeriesBreakdownEntities,
  timeSeriesBreakdownHistory,
  timeSeriesBreakdownRelations,
} from '../../../src/database/middleware';
import { stixRelationshipsMultiTimeSeries, stixRelationshipsTimeSeriesBreakdown } from '../../../src/domain/stixRelationship';
import { INDEX_INFERRED_RELATIONSHIPS, READ_INDEX_HISTORY, READ_RELATIONSHIPS_INDICES } from '../../../src/database/utils';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';
import { READ_ENTITIES_INDICES, READ_INDEX_INFERRED_ENTITIES } from '../../../src/database/utils';

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
    vi.spyOn(accessModule, 'isUserCanAccessStoreElement').mockResolvedValue(true);
    vi.mocked(engine.elList).mockResolvedValue([]);
    mockSchema();
  });

  it('should reject a limit out of bounds', async () => {
    await expect(breakdown({ field: 'creator_id', limit: 0 })).rejects.toThrow('Time series breakdown limit');
    await expect(breakdown({ field: 'creator_id', limit: 51 })).rejects.toThrow('Time series breakdown limit');
    expect(engine.elAggregationCount).not.toHaveBeenCalled();
  });

  it('should reject fields that cannot be broken down', async () => {
    await expect(breakdown({ field: 'description' })).rejects.toThrow('does not support this field');
    await expect(breakdown({ field: 'published' })).rejects.toThrow('does not support this field');
    await expect(breakdown({ field: 'regardingOf' })).rejects.toThrow('does not support this field');
    expect(engine.elAggregationCount).not.toHaveBeenCalled();
  });

  it('should reject relation refs outside the allowlist', async () => {
    await expect(breakdown({ field: 'objects' })).rejects.toThrow('does not support this field');
    await expect(breakdown({ field: 'externalReferences' })).rejects.toThrow('does not support this field');
    expect(engine.elAggregationCount).not.toHaveBeenCalled();
  });

  it('should count the Other series in the maximum number of buckets', async () => {
    // 50 series over 1,000 days fit in 50,000 buckets, 51 do not
    const thousandDaysLater = new Date('2028-09-26T12:00:00.000Z');
    vi.mocked(engine.elAggregationCount).mockResolvedValue([]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());
    await expect(breakdown({ field: 'creator_id', limit: 50, endDate: thousandDaysLater, includeOther: true })).rejects.toThrow('too large');
    await expect(breakdown({ field: 'creator_id', limit: 50, endDate: thousandDaysLater })).resolves.toBeDefined();
  });

  it('should keep the values with the lowest total in asc order', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([
      bucket('user-a', 10),
      bucket('user-b', 5),
      bucket('user-c', 3),
      bucket('user-d', 1),
    ]);
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'user-a': makeEntity('user-a', 'Alice'),
      'user-b': makeEntity('user-b', 'Bob'),
      'user-c': makeEntity('user-c', 'Carol'),
      'user-d': makeEntity('user-d', 'Dave'),
    } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await breakdown({ field: 'creator_id', limit: 2, order: 'asc' });

    expect(result.truncated).toBe(true);
    expect(result.series.map((serie) => (serie.entity as any)?.name)).toEqual(['Dave', 'Carol']);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['user-d', 'user-c']);
  });

  it('should rank the candidates on their number of entities, in the order of the selection', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('user-a', 10)]);
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'user-a': makeEntity('user-a', 'Alice') } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    await breakdown({ field: 'creator_id', order: 'asc' });
    expect(vi.mocked(engine.elAggregationCount).mock.lastCall?.[3]).toMatchObject({ rankByCount: true, bucketsOrder: 'asc' });

    for (const order of ['desc', null, undefined]) {
      await breakdown({ field: 'creator_id', order });
      expect(vi.mocked(engine.elAggregationCount).mock.lastCall?.[3]).toMatchObject({ rankByCount: true, bucketsOrder: 'desc' });
    }
  });

  it('should give each series its weighted total from the histogram, not the number of entities used to rank it', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('user-a', 10)]);
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'user-a': makeEntity('user-a', 'Alice') } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map([
      ['user-a', [{ date: '2026-01-01', value: 2 }, { date: '2026-01-03', value: 1.5 }]],
    ]));

    const result = await breakdown({ field: 'creator_id' });

    expect(result.series[0].values).toEqual([2, 0, 1.5]);
    expect(result.series[0].value).toEqual(3.5);
  });

  it('should use one filter per value in the histogram only when the field has many values', async () => {
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());
    const types = (count: number) => Array.from({ length: count }, (_, i) => ({ key: `type-${i}`, label: `Type-${i}`, value: 100 - i, count: 100 - i }));

    // A handful of values: the restricted terms aggregation is faster
    vi.mocked(engine.elAggregationCount).mockResolvedValue(types(5));
    await breakdown({ field: 'entity_type', limit: 5 });
    expect((vi.mocked(engine.elHistogramBreakdownCount).mock.lastCall?.[3] as any).filterPerKey).toBe(false);

    // Three times more values than series
    vi.mocked(engine.elAggregationCount).mockResolvedValue(types(15));
    await breakdown({ field: 'entity_type', limit: 5 });
    expect((vi.mocked(engine.elHistogramBreakdownCount).mock.lastCall?.[3] as any).filterPerKey).toBe(true);

    // A full candidates page, whatever the limit
    vi.mocked(engine.elAggregationCount).mockResolvedValue(types(engine.MAX_AGGREGATION_SIZE));
    await breakdown({ field: 'entity_type', limit: 50 });
    expect((vi.mocked(engine.elHistogramBreakdownCount).mock.lastCall?.[3] as any).filterPerKey).toBe(true);
  });

  it('should only resolve the candidates needed to fill the limit and know whether more exist', async () => {
    const users = Array.from({ length: 40 }, (_, i) => `user-${i}`);
    vi.mocked(engine.elAggregationCount).mockResolvedValue(users.map((id, i) => bucket(id, 100 - i)));
    vi.mocked(engine.elFindByIds).mockImplementation(async (_context, _user, ids) => Object.fromEntries(
      (ids as string[]).map((id) => [id, makeEntity(id, id)]),
    ) as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await breakdown({ field: 'creator_id', limit: 5 });

    // limit + 10 values at once, enough to fill the limit and see a sixth one
    expect(engine.elFindByIds).toHaveBeenCalledTimes(1);
    expect(vi.mocked(engine.elFindByIds).mock.calls[0][2]).toEqual(users.slice(0, 15));
    expect(result.series).toHaveLength(5);
    expect(result.truncated).toBe(true);
  });

  it('should resolve the next candidates when the first ones cannot be resolved', async () => {
    const users = Array.from({ length: 30 }, (_, i) => `user-${i}`);
    vi.mocked(engine.elAggregationCount).mockResolvedValue(users.map((id, i) => bucket(id, 100 - i)));
    // The 13 first values are unknown entities (like deleted users)
    vi.mocked(engine.elFindByIds).mockImplementation(async (_context, _user, ids) => Object.fromEntries(
      (ids as string[]).filter((id) => Number(id.split('-')[1]) >= 13).map((id) => [id, makeEntity(id, id)]),
    ) as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await breakdown({ field: 'creator_id', limit: 2 });

    expect(engine.elFindByIds).toHaveBeenCalledTimes(2);
    expect(result.series.map((serie) => serie.label)).toEqual(['user-13', 'user-14']);
    expect(result.truncated).toBe(true);
  });

  it('should only query the entities indices', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([]);

    await breakdown({ field: 'entity_type' });
    expect(vi.mocked(engine.elAggregationCount).mock.lastCall?.[2]).toEqual(READ_ENTITIES_INDICES);

    await breakdown({ field: 'entity_type', onlyInferred: true });
    expect(vi.mocked(engine.elAggregationCount).mock.lastCall?.[2]).toEqual([READ_INDEX_INFERRED_ENTITIES]);
  });

  it('should keep a vocabulary value named unknown like any other value', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('unknown', 50), bucket('malicious-activity', 10)]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await breakdown({ field: 'report_types' });

    expect(result.series.map((serie) => serie.label)).toEqual(['unknown', 'malicious-activity']);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['unknown', 'malicious-activity']);
  });

  it('should not order the aggregation of the distribution APIs, whose order only sorts their result', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([]);
    await distributionEntities(mockContext, accessModule.SYSTEM_USER, ['Report'], { field: 'entity_type', order: 'asc', limit: 10 } as any);
    expect((vi.mocked(engine.elAggregationCount).mock.lastCall?.[3] as any).bucketsOrder).toBeUndefined();
    await distributionHistory(mockContext, accessModule.SYSTEM_USER, { field: 'entity_type', order: 'descending', limit: 10 } as any);
    expect((vi.mocked(engine.elAggregationCount).mock.lastCall?.[3] as any).bucketsOrder).toBeUndefined();
  });

  it('should keep the values with the highest total when the order is desc or not given', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('user-c', 3), bucket('user-a', 10), bucket('user-b', 5)]);
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'user-a': makeEntity('user-a', 'Alice'),
      'user-b': makeEntity('user-b', 'Bob'),
      'user-c': makeEntity('user-c', 'Carol'),
    } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    for (const order of ['desc', null, undefined]) {
      const result = await breakdown({ field: 'creator_id', limit: 2, order });
      expect(result.series.map((serie) => (serie.entity as any)?.name)).toEqual(['Alice', 'Bob']);
    }
  });

  it('should not be truncated in asc when every usable value fits and the candidates page is not full', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('user-a', 10), bucket('user-b', 5)]);
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'user-a': makeEntity('user-a', 'Alice'),
      'user-b': makeEntity('user-b', 'Bob'),
    } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await breakdown({ field: 'creator_id', limit: 10, order: 'asc' });

    expect(result.truncated).toBe(false);
  });

  it('should flag a full candidates page as truncated in asc, because the lowest values may be missing', async () => {
    const candidates = Array.from({ length: engine.MAX_AGGREGATION_SIZE }, (_, i) => bucket(`report-${i}`, 100 - i));
    vi.mocked(engine.elAggregationCount).mockResolvedValue(candidates.map((c) => ({ ...c, label: `Report-${c.key}` })));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await breakdown({ field: 'entity_type', limit: 50, order: 'asc' });

    expect(result.truncated).toBe(true);
    // The lowest candidates seen are kept, lowest first
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys[0]).toEqual(`report-${engine.MAX_AGGREGATION_SIZE - 1}`);
  });

  it('should append the Other series last, computed from the reserved histogram key', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('user-a', 10), bucket('user-b', 5)]);
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'user-a': makeEntity('user-a', 'Alice'),
      'user-b': makeEntity('user-b', 'Bob'),
    } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map([
      ['user-a', [{ date: '2026-01-02', value: 4 }]],
      [engine.HISTOGRAM_BREAKDOWN_OTHER_KEY, [{ date: '2026-01-01', value: 2 }, { date: '2026-01-03', value: 5 }]],
    ]));

    const result = await breakdown({ field: 'creator_id', limit: 2, includeOther: true });

    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].withOther).toBe(true);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['user-a', 'user-b']);
    expect(engine.elHistogramBreakdownCount).toHaveBeenCalledTimes(1);
    expect(result.series.map((serie) => serie.isOther)).toEqual([false, false, true]);
    const other = result.series[2];
    expect(other.label).toEqual('Other');
    expect(other.entity).toBeNull();
    expect(other.value).toEqual(7);
    expect(other.values).toEqual([2, 0, 5]);
    // The dates are sent once, shared by every series
    expect(result.dates).toEqual(['2026-01-01T00:00:00.000Z', '2026-01-02T00:00:00.000Z', '2026-01-03T00:00:00.000Z']);
    expect(result.series.every((serie) => serie.values.length === result.dates.length)).toBe(true);
  });

  it('should not add the Other series unless it is requested', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('user-a', 10)]);
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'user-a': makeEntity('user-a', 'Alice') } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    for (const includeOther of [false, null, undefined]) {
      const result = await breakdown({ field: 'creator_id', includeOther });
      expect(result.series).toHaveLength(1);
      expect(result.series[0].isOther).toBe(false);
      expect(vi.mocked(engine.elHistogramBreakdownCount).mock.lastCall?.[3].withOther).toBe(false);
    }
  });

  it('should still count the Other series when no usable value is found', async () => {
    // Not resolvable, like the SYSTEM user
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('system', 3)]);
    vi.mocked(engine.elFindByIds).mockResolvedValue({} as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map([
      [engine.HISTOGRAM_BREAKDOWN_OTHER_KEY, [{ date: '2026-01-02', value: 3 }]],
    ]));

    const result = await breakdown({ field: 'creator_id', includeOther: true });

    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual([]);
    expect(result.series.map((serie) => serie.label)).toEqual(['Other']);
    expect(result.series[0].value).toEqual(3);
  });

  it('should reject an unsupported interval before querying', async () => {
    const actualEngine = await vi.importActual<typeof engine>('../../../src/database/engine');
    vi.mocked(engine.getHistogramDateFormat).mockImplementation(actualEngine.getHistogramDateFormat);

    await expect(breakdown({ field: 'creator_id', interval: 'minute' })).rejects.toThrow('Unsupported interval');
    expect(engine.elAggregationCount).not.toHaveBeenCalled();
  });

  it('should end the period now when no end date is given', async () => {
    // Without it, the histogram would create a bucket for every day up to the most recent entity
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('user-a', 10)]);
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'user-a': makeEntity('user-a', 'Alice') } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());
    const recentStartDate = new Date(Date.now() - 2 * 86400000);

    const before = Date.now();
    const result = await breakdown({ field: 'creator_id', startDate: recentStartDate, endDate: undefined });

    const histogramOptions = vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3] as any;
    expect(histogramOptions.endDate).toBeInstanceOf(Date);
    expect(histogramOptions.endDate.getTime()).toBeGreaterThanOrEqual(before);
    expect((vi.mocked(engine.elAggregationCount).mock.calls[0][3] as any).endDate).toEqual(histogramOptions.endDate);
    expect(result.dates).toHaveLength(3);
  });

  it('should reject a breakdown exceeding the maximum number of buckets', async () => {
    const threeYearsLater = new Date('2029-01-01T12:00:00.000Z');
    await expect(breakdown({ field: 'creator_id', limit: 50, endDate: threeYearsLater })).rejects.toThrow('too large');
    expect(engine.elAggregationCount).not.toHaveBeenCalled();
  });

  it('should drop unresolved values before applying the limit', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([
      bucket('user-a', 10),
      bucket('system', 7), // not resolvable, like the SYSTEM user
      bucket('user-b', 5),
      bucket('user-c', 3),
    ]);
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'user-a': makeEntity('user-a', 'Alice'),
      'user-b': makeEntity('user-b', 'Bob'),
      'user-c': makeEntity('user-c', 'Carol'),
    } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map([
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
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('user-a', 10), bucket('system', 2)]);
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'user-a': makeEntity('user-a', 'Alice') } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await breakdown({ field: 'creator_id', limit: 10 });

    expect(result.truncated).toBe(false);
    expect(result.series).toHaveLength(1);
  });

  it('should flag a full candidates page as truncated', async () => {
    const candidates = Array.from({ length: engine.MAX_AGGREGATION_SIZE }, (_, i) => bucket(`report-${i}`, 100 - i));
    vi.mocked(engine.elAggregationCount).mockResolvedValue(candidates.map((c) => ({ ...c, label: `Report-${c.key}` })));
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await breakdown({ field: 'entity_type', limit: 50 });

    expect(result.truncated).toBe(true);
    expect(result.series).toHaveLength(50);
  });

  it('should name the vocabulary values after their vocabulary, read for the values kept only', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('reseau interne', 9), bucket('threat-report', 5), bucket('no-vocabulary', 3), bucket('dropped', 1)]);
    vi.mocked(engine.elList).mockResolvedValue([{ name: 'Réseau Interne' }, { name: 'threat-report' }] as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await breakdown({ field: 'report_types', limit: 3 });

    // A value without vocabulary keeps its indexed form
    expect(result.series.map((serie) => serie.label)).toEqual(['Réseau Interne', 'threat-report', 'no-vocabulary']);
    // The histogram still targets the indexed values
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['reseau interne', 'threat-report', 'no-vocabulary']);
    expect(engine.elList).toHaveBeenCalledTimes(1);
    const [, vocabularyUser, , vocabularyOptions] = vi.mocked(engine.elList).mock.calls[0] as any[];
    expect(vocabularyUser).toBe(accessModule.SYSTEM_USER);
    const collectFilters = (group: any): any[] => [...group.filters, ...group.filterGroups.flatMap(collectFilters)];
    const vocabularyFilters = collectFilters(vocabularyOptions.filters);
    expect(vocabularyFilters).toEqual(expect.arrayContaining([
      expect.objectContaining({ key: ['category'], values: ['report_types_ov'] }),
      expect.objectContaining({ key: ['name'], values: ['reseau interne', 'threat-report', 'no-vocabulary'] }),
    ]));
  });

  it('should name the enum values as they are written in the schema, without reading anything', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('critical', 4), bucket('unknown', 2), bucket('not-in-schema', 1)]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await breakdown({ field: 'x_opencti_cvss_base_severity' });

    expect(result.series.map((serie) => serie.label)).toEqual(['CRITICAL', 'Unknown', 'not-in-schema']);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['critical', 'unknown', 'not-in-schema']);
    expect(engine.elList).not.toHaveBeenCalled();
  });

  it('should keep the converted label and no entity for entity types', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([
      { key: 'intrusion-set', label: 'Intrusion-Set', value: 6, count: 6 },
      { key: 'malware', label: 'Malware', value: 4, count: 4 },
    ]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await breakdown({ field: 'entity_type' });

    expect(engine.elFindByIds).not.toHaveBeenCalled();
    expect(result.series.map((serie) => serie.label)).toEqual(['Intrusion-Set', 'Malware']);
    expect(result.series.every((serie) => serie.entity === null)).toBe(true);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['intrusion-set', 'malware']);
  });

  it('should query both aggregations with the same filters, field and inclusive bounds', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('label-a', 4)]);
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'label-a': makeEntity('label-a', 'tlp') } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());
    const filters = { mode: 'and', filters: [{ key: ['confidence'], values: ['50'], operator: 'gt' }], filterGroups: [] };

    await breakdown({ field: 'objectLabel', dateAttribute: 'published', filters });

    const discoveryOptions = vi.mocked(engine.elAggregationCount).mock.calls[0][3] as any;
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

  it('should skip the histogram query when no value is found', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([]);

    const result = await breakdown({ field: 'creator_id' });

    expect(result).toEqual({ truncated: false, dates: [], series: [] });
    expect(engine.elHistogramBreakdownCount).not.toHaveBeenCalled();
  });

  it('should not read the vocabularies when only the Other series is counted', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await breakdown({ field: 'report_types', includeOther: true });

    expect(result.series.map((serie) => serie.isOther)).toEqual([true]);
    expect(engine.elList).not.toHaveBeenCalled();
  });
});

describe('resolveBreakdownField', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSchema();
  });

  it('should aggregate relation refs on their denormalized ids and resolve their entities', () => {
    expect(resolveBreakdownField(['Report'], 'createdBy')).toEqual({ aggregationField: 'rel_created-by.internal_id', resolveEntities: true });
  });

  it('should aggregate id, vocabulary and enum attributes as they are', () => {
    expect(resolveBreakdownField(['Report'], 'creator_id')).toEqual({ aggregationField: 'creator_id', resolveEntities: true });
    expect(resolveBreakdownField(['Report'], 'report_types')).toEqual({ aggregationField: 'report_types', resolveEntities: false, vocabularyCategories: ['report_types_ov'] });
    expect(resolveBreakdownField(['Report'], 'x_opencti_cvss_base_severity')).toMatchObject({ aggregationField: 'x_opencti_cvss_base_severity', resolveEntities: false });
    expect(resolveBreakdownField(['Report', 'Malware'], 'entity_type')).toEqual({ aggregationField: 'entity_type', resolveEntities: false });
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
    vi.spyOn(accessModule, 'isUserCanAccessStoreElement').mockResolvedValue(true);
    vi.spyOn(schemaAttributesDefinition, 'getRegisteredTypes').mockReturnValue(['History', 'Activity', 'Report', 'Intrusion-Set', 'PublicDashboard', 'uses']);
  });

  it('should refuse a field outside the allowlist before querying', async () => {
    await expect(historyBreakdown({ field: 'context_data.id' })).rejects.toThrow('does not support this field');
    await expect(historyBreakdown({ field: 'context_data.message' })).rejects.toThrow('does not support this field');
    expect(engine.elAggregationCount).not.toHaveBeenCalled();
  });

  it('should check the limit and the size of the breakdown like the entities', async () => {
    await expect(historyBreakdown({ field: 'event_scope', limit: 51 })).rejects.toThrow('Time series breakdown limit');
    const threeYearsLater = new Date('2029-01-01T12:00:00.000Z');
    await expect(historyBreakdown({ field: 'event_scope', limit: 50, endDate: threeYearsLater })).rejects.toThrow('too large');
    expect(engine.elAggregationCount).not.toHaveBeenCalled();
  });

  it('should query the logs index with the types, filters and history filtering of the caller, on the timestamp', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('create', 4)]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());
    const filters = { mode: 'and', filters: [{ key: ['event_type'], values: ['mutation'], operator: 'eq' }], filterGroups: [] };

    await historyBreakdown({ field: 'event_scope', filters, search: 'report' });

    const [, , discoveryIndices, discoveryOptions] = vi.mocked(engine.elAggregationCount).mock.calls[0] as any[];
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
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('create', 4)]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    await historyBreakdown({ field: 'event_scope', historyFiltering: undefined, types: undefined });

    for (const call of [vi.mocked(engine.elAggregationCount).mock.calls[0], vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0]]) {
      const options = call[3] as any;
      expect(options.historyFiltering).toBe(true);
      // Without types, only the history, like the other logs aggregations
      expect(options.types).toEqual(['History']);
    }
  });

  it('should keep a date attribute given by the widget, and end the period now without end date', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('create', 4)]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());
    const recentStartDate = new Date(Date.now() - 2 * 86400000);

    const before = Date.now();
    const result = await historyBreakdown({ field: 'event_scope', dateAttribute: 'created_at', startDate: recentStartDate, endDate: undefined });

    const histogramOptions = vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3] as any;
    expect(histogramOptions.dateAttribute).toEqual('created_at');
    expect(histogramOptions.endDate.getTime()).toBeGreaterThanOrEqual(before);
    expect(result.dates).toHaveLength(3);
  });

  it('should keep the raw values of the event fields, without entity, ranked on their number of events', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('update', 2), bucket('create', 6)]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map([['create', [{ date: '2026-01-02', value: 6 }]]]));

    const result = await historyBreakdown({ field: 'event_scope', order: 'desc' });

    expect(vi.mocked(engine.elAggregationCount).mock.calls[0][3]).toMatchObject({ rankByCount: true, bucketsOrder: 'desc' });
    expect(engine.elFindByIds).not.toHaveBeenCalled();
    expect(result.series.map((serie) => serie.label)).toEqual(['create', 'update']);
    expect(result.series.every((serie) => serie.entity === null)).toBe(true);
    expect(result.series[0]).toMatchObject({ value: 6, values: [0, 6, 0] });
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['create', 'update']);
  });

  it('should drop the SYSTEM user and the deleted users before applying the limit', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([
      bucket(accessModule.SYSTEM_USER.id, 50),
      bucket('user-a', 10),
      bucket('deleted-user', 8),
      bucket('user-b', 5),
      bucket('user-c', 3),
    ]);
    // Neither the SYSTEM user nor a deleted user is stored
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'user-a': makeEntity('user-a', 'Alice'),
      'user-b': makeEntity('user-b', 'Bob'),
      'user-c': makeEntity('user-c', 'Carol'),
    } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await historyBreakdown({ field: 'user_id', limit: 2 });

    expect(result.truncated).toBe(true);
    expect(result.series.map((serie) => (serie.entity as any)?.name)).toEqual(['Alice', 'Bob']);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['user-a', 'user-b']);
  });

  it('should restrict the users, groups and organizations the user cannot access', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('org-a', 10), bucket('org-b', 5)]);
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'org-a': { ...makeEntity('org-a', 'Filigran'), entity_type: 'Organization' },
      'org-b': { ...makeEntity('org-b', 'Hidden'), entity_type: 'Organization' },
    } as any);
    vi.mocked(accessModule.isUserCanAccessStoreElement).mockImplementation(async (_context, _user, element: any) => element.id === 'org-a');
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await historyBreakdown({ field: 'organization_ids' });

    expect(result.series.map((serie) => (serie.entity as any)?.name)).toEqual(['Filigran', 'Restricted']);
    expect(result.series[1].label).toEqual('org-b');
  });

  it('should name the indexed entity types after their registered type', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([
      bucket('report', 6),
      bucket('intrusion-set', 4),
      bucket('publicdashboard', 3),
      bucket('uses', 2),
      bucket('not-registered', 1),
    ]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await historyBreakdown({ field: 'context_data.entity_type' });

    expect(result.series.map((serie) => serie.label)).toEqual(['Report', 'Intrusion-Set', 'PublicDashboard', 'uses', 'not-registered']);
    // The histogram still targets the values as indexed
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual(['report', 'intrusion-set', 'publicdashboard', 'uses', 'not-registered']);

    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('history', 6), bucket('activity', 4)]);
    const byLogType = await historyBreakdown({ field: 'entity_type' });
    expect(byLogType.series.map((serie) => serie.label)).toEqual(['History', 'Activity']);
  });

  it('should add the Other series of the events with none of the displayed values', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('create', 6), bucket('update', 2)]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map([
      [engine.HISTOGRAM_BREAKDOWN_OTHER_KEY, [{ date: '2026-01-01', value: 3 }]],
    ]));

    const result = await historyBreakdown({ field: 'event_scope', limit: 1, includeOther: true });

    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3]).toMatchObject({ keys: ['create'], withOther: true });
    expect(result.series.map((serie) => serie.label)).toEqual(['create', 'Other']);
    expect(result.series[1]).toMatchObject({ isOther: true, value: 3, values: [3, 0, 0] });
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
  });

  it('should break relationships down by their type, as indexed', () => {
    expect(resolveRelationshipBreakdownField(['stix-relationship'], 'relationship_type')).toEqual({
      aggregationField: 'relationship_type',
      resolveEntities: false,
    });
  });

  it('should break relationships down by the type of their source or of their target', () => {
    expect(resolveRelationshipBreakdownField(['uses'], 'fromTypes')).toEqual({ aggregationField: 'connections.types', resolveEntities: false, connectionSide: 'from' });
    expect(resolveRelationshipBreakdownField(['uses'], 'toTypes')).toEqual({ aggregationField: 'connections.types', resolveEntities: false, connectionSide: 'to' });
  });

  it('should accept the author, labels, markings and creators of the relationships', () => {
    const types = ['uses', 'targets'];
    expect(resolveRelationshipBreakdownField(types, 'createdBy')).toEqual({ aggregationField: 'rel_created-by.internal_id', resolveEntities: true });
    expect(resolveRelationshipBreakdownField(types, 'objectLabel')).toEqual({ aggregationField: 'rel_object-label.internal_id', resolveEntities: true });
    expect(resolveRelationshipBreakdownField(types, 'objectMarking')).toEqual({ aggregationField: 'rel_object-marking.internal_id', resolveEntities: true });
    expect(resolveRelationshipBreakdownField(types, 'creator_id')).toEqual({ aggregationField: 'creator_id', resolveEntities: true });
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
    vi.spyOn(accessModule, 'isUserCanAccessStoreElement').mockResolvedValue(true);
    mockRelationshipSchema();
  });

  it('should reject a limit out of bounds and the fields that cannot be broken down', async () => {
    await expect(relationsBreakdown({ field: 'relationship_type', limit: 0 })).rejects.toThrow('Time series breakdown limit');
    await expect(relationsBreakdown({ field: 'relationship_type', limit: 51 })).rejects.toThrow('Time series breakdown limit');
    await expect(relationsBreakdown({ field: 'fromId' })).rejects.toThrow('does not support this field for these relationship types');
    expect(engine.elAggregationCount).not.toHaveBeenCalled();
    expect(engine.elConnectionTypesAggregationCount).not.toHaveBeenCalled();
  });

  it('should count the relationships of the requested types in the relationships indices', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('uses', 5)]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());
    const filters = { mode: 'and', filters: [{ key: ['confidence'], values: ['50'], operator: 'gt' }], filterGroups: [] };

    await relationsBreakdown({ field: 'relationship_type', dateAttribute: 'start_time', filters });

    const [, , discoveryIndices, discoveryOptions] = vi.mocked(engine.elAggregationCount).mock.calls[0] as any[];
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
    expect(vi.mocked(engine.elAggregationCount).mock.lastCall?.[2]).toEqual(INDEX_INFERRED_RELATIONSHIPS);
  });

  it('should keep the relationship type as label, without entity', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('uses', 5), bucket('targets', 3)]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map([
      ['uses', [{ date: '2026-01-02', value: 5 }]],
      ['targets', [{ date: '2026-01-01', value: 1 }, { date: '2026-01-03', value: 2 }]],
    ]));

    const result = await relationsBreakdown({ field: 'relationship_type' });

    expect(engine.elFindByIds).not.toHaveBeenCalled();
    expect(engine.elConnectionTypesAggregationCount).not.toHaveBeenCalled();
    // Ranked on their number of relationships, like the fields of the entities
    expect(vi.mocked(engine.elAggregationCount).mock.calls[0][3]).toMatchObject({ field: 'relationship_type', rankByCount: true, bucketsOrder: 'desc' });
    expect(result.series.map((serie) => [serie.label, serie.value, serie.entity])).toEqual([['uses', 5, null], ['targets', 3, null]]);
    expect(result.series.map((serie) => serie.values)).toEqual([[0, 5, 0], [1, 0, 2]]);
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].connectionSide).toBeUndefined();
  });

  it('should break down by the type of the source through the connections of the relationships', async () => {
    vi.mocked(engine.elConnectionTypesAggregationCount).mockResolvedValue([
      { key: 'malware', label: 'Malware', value: 4, count: 4 },
      { key: 'intrusion-set', label: 'Intrusion-Set', value: 2, count: 2 },
    ]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map([
      ['malware', [{ date: '2026-01-01', value: 4 }]],
      [engine.HISTOGRAM_BREAKDOWN_OTHER_KEY, [{ date: '2026-01-03', value: 1 }]],
    ]));

    const result = await relationsBreakdown({ field: 'fromTypes', includeOther: true });

    expect(engine.elAggregationCount).not.toHaveBeenCalled();
    const discoveryOptions = vi.mocked(engine.elConnectionTypesAggregationCount).mock.calls[0][3];
    expect(discoveryOptions).toMatchObject({ connectionSide: 'from', bucketsOrder: 'desc', types: ['uses', 'targets'], intervalInclude: true });
    const histogramOptions = vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3];
    expect(histogramOptions).toMatchObject({ connectionSide: 'from', keys: ['malware', 'intrusion-set'], withOther: true });
    expect(result.series.map((serie) => [serie.label, serie.value, serie.entity, serie.isOther])).toEqual([
      ['Malware', 4, null, false],
      // The value of a series is the sum of its values: no histogram bucket, no relationship
      ['Intrusion-Set', 0, null, false],
      ['Other', 1, null, true],
    ]);
    expect(result.series[2].values).toEqual([0, 0, 1]);
  });

  it('should break down by the type of the target, lowest values first in asc order', async () => {
    vi.mocked(engine.elConnectionTypesAggregationCount).mockResolvedValue([
      { key: 'sector', label: 'Sector', value: 6, count: 6 },
      { key: 'country', label: 'Country', value: 1, count: 1 },
    ]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await relationsBreakdown({ field: 'toTypes', order: 'asc', limit: 1 });

    expect(vi.mocked(engine.elConnectionTypesAggregationCount).mock.calls[0][3]).toMatchObject({ connectionSide: 'to', bucketsOrder: 'asc' });
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3]).toMatchObject({ connectionSide: 'to', keys: ['country'] });
    expect(result.truncated).toBe(true);
    expect(result.series.map((serie) => serie.label)).toEqual(['Country']);
  });

  it('should resolve the authors of the relationships, restricted ones included', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('identity-a', 3), bucket('identity-b', 2)]);
    vi.mocked(engine.elFindByIds).mockResolvedValue({
      'identity-a': makeEntity('identity-a', 'Filigran'),
      'identity-b': makeEntity('identity-b', 'Secret'),
    } as any);
    vi.mocked(accessModule.isUserCanAccessStoreElement).mockImplementation(async (_context, _user, element: any) => element.internal_id === 'identity-a');
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    const result = await relationsBreakdown({ field: 'createdBy' });

    expect((vi.mocked(engine.elAggregationCount).mock.calls[0][3] as any).field).toEqual('rel_created-by.internal_id');
    expect(result.series.map((serie) => (serie.entity as any)?.name)).toEqual(['Filigran', 'Restricted']);
  });

  it('should count the Other series in the maximum number of buckets and end the period now', async () => {
    const thousandDaysLater = new Date('2028-09-26T12:00:00.000Z');
    await expect(relationsBreakdown({ field: 'relationship_type', limit: 50, endDate: thousandDaysLater, includeOther: true })).rejects.toThrow('too large');
    expect(engine.elAggregationCount).not.toHaveBeenCalled();

    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('uses', 1)]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());
    const before = Date.now();
    const result = await relationsBreakdown({ field: 'relationship_type', startDate: new Date(Date.now() - 2 * 86400000), endDate: undefined });
    const histogramOptions = vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3] as any;
    expect(histogramOptions.endDate.getTime()).toBeGreaterThanOrEqual(before);
    expect(result.dates).toHaveLength(3);
  });

  it('should reject an unsupported interval before querying', async () => {
    const actualEngine = await vi.importActual<typeof engine>('../../../src/database/engine');
    vi.mocked(engine.getHistogramDateFormat).mockImplementation(actualEngine.getHistogramDateFormat);

    await expect(relationsBreakdown({ field: 'fromTypes', interval: 'minute' })).rejects.toThrow('Unsupported interval');
    expect(engine.elConnectionTypesAggregationCount).not.toHaveBeenCalled();
  });

  it('should not break the entities down through the connections', async () => {
    mockSchema();
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('report', 1)]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    await breakdown({ field: 'entity_type' });

    expect(engine.elConnectionTypesAggregationCount).not.toHaveBeenCalled();
    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].connectionSide).toBeUndefined();
  });
});

describe('stixRelationshipsTimeSeriesBreakdown', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRelationshipSchema();
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('targets', 4)]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());
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
    const discoveryOptions = vi.mocked(engine.elAggregationCount).mock.calls[0][3] as any;
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
    expect((vi.mocked(engine.elAggregationCount).mock.calls[0][3] as any).types).toEqual(['uses']);
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
