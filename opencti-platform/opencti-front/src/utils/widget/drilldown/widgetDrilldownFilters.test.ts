import { afterEach, describe, expect, it } from 'vitest';
import moment from 'moment';
import { buildBucketDateFilter, buildBucketValueFilter, assertRepresentable } from './widgetDrilldownFilters';

const NO_RANGE = { startDate: null, endDate: null };

/**
 * Reproduces what the API actually returns for the bucket starting on the given
 * calendar date. `fillTimeSeries` builds period starts in the browser's offset
 * then converts to UTC, so the instant depends on the timezone of the process:
 * a CET browser receives `2024-01-31T23:00:00.000Z` for February 2024.
 *
 * Fixtures must therefore be derived, never hardcoded — a hardcoded UTC
 * midnight describes a bucket no browser east or west of UTC could ever emit,
 * and would make the timezone sweep below pass for the wrong reason.
 */
const apiBucketDate = (periodStart: string) => moment(periodStart, 'YYYY-MM-DD').utc().toISOString();

describe('buildBucketDateFilter', () => {
  it('builds an inclusive lower bound and an exclusive upper bound', () => {
    const filters = buildBucketDateFilter(apiBucketDate('2024-03-01'), 'month', NO_RANGE, 'created_at');
    expect(filters).toEqual([
      { key: 'created_at', values: ['2024-03-01T00:00:00.000Z'], operator: 'gte', mode: 'or' },
      { key: 'created_at', values: ['2024-04-01T00:00:00.000Z'], operator: 'lt', mode: 'or' },
    ]);
  });

  it('handles each supported interval', () => {
    expect(buildBucketDateFilter(apiBucketDate('2024-03-04'), 'day', NO_RANGE, 'created_at')?.[1].values[0])
      .toEqual('2024-03-05T00:00:00.000Z');
    // 2024-03-04 is a Monday, matching Elasticsearch's week start.
    expect(buildBucketDateFilter(apiBucketDate('2024-03-04'), 'week', NO_RANGE, 'created_at')?.[1].values[0])
      .toEqual('2024-03-11T00:00:00.000Z');
    expect(buildBucketDateFilter(apiBucketDate('2024-04-01'), 'quarter', NO_RANGE, 'created_at')?.[1].values[0])
      .toEqual('2024-07-01T00:00:00.000Z');
    expect(buildBucketDateFilter(apiBucketDate('2024-01-01'), 'year', NO_RANGE, 'created_at')?.[1].values[0])
      .toEqual('2025-01-01T00:00:00.000Z');
  });

  it('clamps the first bucket to the widget start date', () => {
    const range = { startDate: '2024-01-15T00:00:00.000Z', endDate: null };
    const filters = buildBucketDateFilter(apiBucketDate('2024-01-01'), 'month', range, 'created_at');
    expect(filters?.[0]).toEqual({
      key: 'created_at', values: ['2024-01-15T00:00:00.000Z'], operator: 'gte', mode: 'or',
    });
    expect(filters?.[1].values[0]).toEqual('2024-02-01T00:00:00.000Z');
  });

  it('clamps the last bucket to the widget end date and switches to lte', () => {
    const range = { startDate: null, endDate: '2024-03-20T00:00:00.000Z' };
    const filters = buildBucketDateFilter(apiBucketDate('2024-03-01'), 'month', range, 'created_at');
    expect(filters?.[1]).toEqual({
      key: 'created_at', values: ['2024-03-20T00:00:00.000Z'], operator: 'lte', mode: 'or',
    });
  });

  it('does not clamp a middle bucket', () => {
    const range = { startDate: '2024-01-15T00:00:00.000Z', endDate: '2024-05-20T00:00:00.000Z' };
    const filters = buildBucketDateFilter(apiBucketDate('2024-03-01'), 'month', range, 'created_at');
    expect(filters?.[0].operator).toEqual('gte');
    expect(filters?.[1].operator).toEqual('lt');
  });

  it('uses the configured date attribute', () => {
    const filters = buildBucketDateFilter(apiBucketDate('2024-03-01'), 'month', NO_RANGE, 'published');
    expect(filters?.every((f) => f.key === 'published')).toBe(true);
  });

  it('returns null for an unsupported interval', () => {
    expect(buildBucketDateFilter(apiBucketDate('2024-03-01'), 'fortnight', NO_RANGE, 'created_at')).toBeNull();
  });

  it('returns null for an invalid date', () => {
    expect(buildBucketDateFilter('not-a-date', 'month', NO_RANGE, 'created_at')).toBeNull();
  });
});

describe('buildBucketDateFilter timezone recovery', () => {
  const originalTz = process.env.TZ;

  afterEach(() => {
    if (originalTz === undefined) delete process.env.TZ;
    else process.env.TZ = originalTz;
  });

  /**
   * The February 2024 bucket as emitted by a browser in each zone. Elasticsearch
   * counted the true UTC month in every case, so all three must resolve to the
   * same boundaries whatever the timezone of the process running the test.
   */
  it.each([
    ['Europe/Paris', '2024-01-31T23:00:00.000Z'],
    ['Pacific/Kiritimati', '2024-01-31T10:00:00.000Z'],
    ['Pacific/Midway', '2024-02-01T11:00:00.000Z'],
    ['UTC', '2024-02-01T00:00:00.000Z'],
  ])('recovers the February 2024 boundaries from a date skewed by %s', (timezone, bucketDate) => {
    process.env.TZ = timezone;
    const filters = buildBucketDateFilter(bucketDate, 'month', NO_RANGE, 'created_at');
    expect(filters?.[0].values[0]).toEqual('2024-02-01T00:00:00.000Z');
    expect(filters?.[1].values[0]).toEqual('2024-03-01T00:00:00.000Z');
  });
});

const schemaWith = (keys: string[]) => new Map([
  ['Stix-Core-Object', new Map(keys.map((k) => [k, { filterKey: k } as never]))],
]);

const SCHEMA = schemaWith([
  'entity_type', 'createdBy', 'objectLabel', 'objectMarking',
  'objectAssignee', 'killChainPhases', 'creator_id', 'x_opencti_workflow_id',
]);

describe('buildBucketValueFilter', () => {
  it('maps entity_type to the raw label', () => {
    const bucket = { kind: 'distribution', rawValue: 'Malware', entityId: null } as const;
    expect(buildBucketValueFilter('entity_type', bucket, ['Stix-Core-Object'], SCHEMA)).toEqual([
      { key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' },
    ]);
  });

  it('maps a nested internal_id attribute to its filter key and the entity id', () => {
    const bucket = { kind: 'distribution', rawValue: 'id-1', entityId: 'id-1' } as const;
    expect(buildBucketValueFilter('created-by.internal_id', bucket, ['Stix-Core-Object'], SCHEMA)).toEqual([
      { key: 'createdBy', values: ['id-1'], operator: 'eq', mode: 'or' },
    ]);
  });

  it('maps every supported id-based attribute', () => {
    const bucket = { kind: 'distribution', rawValue: 'x', entityId: 'x' } as const;
    const pairs: [string, string][] = [
      ['object-label.internal_id', 'objectLabel'],
      ['object-marking.internal_id', 'objectMarking'],
      ['object-assignee.internal_id', 'objectAssignee'],
      ['kill-chain-phase.internal_id', 'killChainPhases'],
      ['creator_id', 'creator_id'],
    ];
    pairs.forEach(([attribute, key]) => {
      expect(buildBucketValueFilter(attribute, bucket, ['Stix-Core-Object'], SCHEMA)?.[0].key).toEqual(key);
    });
  });

  it('returns null when an id-based bucket has no resolved entity', () => {
    const bucket = { kind: 'distribution', rawValue: 'id-1', entityId: null } as const;
    expect(buildBucketValueFilter('created-by.internal_id', bucket, ['Stix-Core-Object'], SCHEMA)).toBeNull();
  });

  it('returns null for an unmapped attribute', () => {
    const bucket = { kind: 'distribution', rawValue: 'a', entityId: null } as const;
    expect(buildBucketValueFilter('some_custom_field', bucket, ['Stix-Core-Object'], SCHEMA)).toBeNull();
  });

  it('returns null when the filter key is not supported by the destination schema', () => {
    const bucket = { kind: 'distribution', rawValue: 'id-1', entityId: 'id-1' } as const;
    const poorSchema = schemaWith(['entity_type']);
    expect(buildBucketValueFilter('created-by.internal_id', bucket, ['Stix-Core-Object'], poorSchema)).toBeNull();
  });

  it('returns null for an empty bucket value', () => {
    const bucket = { kind: 'distribution', rawValue: null, entityId: null } as const;
    expect(buildBucketValueFilter('entity_type', bucket, ['Stix-Core-Object'], SCHEMA)).toBeNull();
  });

  // `terms.missing = 'unknown'` (engine.ts:3384) makes this a real bucket with a
  // real count, but `entity_type = 'unknown'` would match nothing.
  it('returns null for the missing-value sentinel bucket', () => {
    const bucket = { kind: 'distribution', rawValue: 'unknown', entityId: null } as const;
    expect(buildBucketValueFilter('entity_type', bucket, ['Stix-Core-Object'], SCHEMA)).toBeNull();
  });

  it('returns an empty filter list for a total bucket', () => {
    expect(buildBucketValueFilter('entity_type', { kind: 'total' }, ['Stix-Core-Object'], SCHEMA)).toEqual([]);
  });
});

describe('assertRepresentable', () => {
  it('accepts a plain filter group', () => {
    expect(assertRepresentable({ mode: 'and', filters: [{ key: 'entity_type', values: ['Malware'], mode: 'or' }], filterGroups: [] })).toBe(true);
  });

  it('accepts an undefined filter group', () => {
    expect(assertRepresentable(undefined)).toBe(true);
  });

  it('rejects a dynamicFrom filter', () => {
    expect(assertRepresentable({ mode: 'and', filters: [{ key: 'dynamicFrom', values: ['x'], mode: 'or' }], filterGroups: [] })).toBe(false);
  });

  it('rejects a dynamicTo filter nested in a sub-group', () => {
    const nested = { mode: 'and', filters: [{ key: 'dynamicTo', values: ['x'], mode: 'or' }], filterGroups: [] };
    expect(assertRepresentable({ mode: 'and', filters: [], filterGroups: [nested] })).toBe(false);
  });
});
