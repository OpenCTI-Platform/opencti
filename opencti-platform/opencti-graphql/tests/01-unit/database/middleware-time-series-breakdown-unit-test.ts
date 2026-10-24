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
import { BREAKDOWN_ALLOWED_REFS, resolveBreakdownField, timeSeriesBreakdownEntities } from '../../../src/database/middleware';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';

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
const ATTRIBUTES: Record<string, { type: string; format?: string }> = {
  creator_id: { type: 'string', format: 'id' },
  pir_ids: { type: 'string', format: 'id' },
  report_types: { type: 'string', format: 'vocabulary' },
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

  it('should forward the asc order to the candidates aggregation only in asc', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('user-a', 10)]);
    vi.mocked(engine.elFindByIds).mockResolvedValue({ 'user-a': makeEntity('user-a', 'Alice') } as any);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map());

    await breakdown({ field: 'creator_id', order: 'asc' });
    expect((vi.mocked(engine.elAggregationCount).mock.lastCall?.[3] as any).order).toEqual('asc');

    for (const order of ['desc', null, undefined]) {
      await breakdown({ field: 'creator_id', order });
      expect((vi.mocked(engine.elAggregationCount).mock.lastCall?.[3] as any).order).toBeUndefined();
    }
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
    expect(other.data.map((point) => point.value)).toEqual([2, 0, 5]);
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
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('unknown', 3)]);
    vi.mocked(engine.elHistogramBreakdownCount).mockResolvedValue(new Map([
      [engine.HISTOGRAM_BREAKDOWN_OTHER_KEY, [{ date: '2026-01-02', value: 3 }]],
    ]));

    const result = await breakdown({ field: 'creator_id', includeOther: true });

    expect(vi.mocked(engine.elHistogramBreakdownCount).mock.calls[0][3].keys).toEqual([]);
    expect(result.series.map((serie) => serie.label)).toEqual(['Other']);
    expect(result.series[0].value).toEqual(3);
  });

  it('should reject a breakdown exceeding the maximum number of buckets', async () => {
    const threeYearsLater = new Date('2029-01-01T12:00:00.000Z');
    await expect(breakdown({ field: 'creator_id', limit: 50, endDate: threeYearsLater })).rejects.toThrow('too large');
    expect(engine.elAggregationCount).not.toHaveBeenCalled();
  });

  it('should drop unknown and unresolved values before applying the limit', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([
      bucket('user-a', 10),
      bucket('unknown', 8),
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
    expect(result.series[0].data.map((point) => point.value)).toEqual([0, 4, 0]);
    // A value without any histogram bucket still gets a full zero series
    expect(result.series[1].data.map((point) => point.value)).toEqual([0, 0, 0]);
  });

  it('should not be truncated when every usable value fits in the limit', async () => {
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('user-a', 10), bucket('unknown', 2)]);
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
    vi.mocked(engine.elAggregationCount).mockResolvedValue([bucket('unknown', 3)]);

    const result = await breakdown({ field: 'creator_id' });

    expect(result).toEqual({ truncated: false, series: [] });
    expect(engine.elHistogramBreakdownCount).not.toHaveBeenCalled();
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
    expect(resolveBreakdownField(['Report'], 'report_types')).toEqual({ aggregationField: 'report_types', resolveEntities: false });
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
