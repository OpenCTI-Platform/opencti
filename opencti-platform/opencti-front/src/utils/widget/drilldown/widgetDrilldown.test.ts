import { describe, expect, it } from 'vitest';
import { resolveDrilldownLink } from './widgetDrilldown';
import type { DrilldownInput, FilterGroup } from './widgetDrilldown-types';
import type { Filter } from '../../filters/filtersHelpers-types';

const SCHEMA = new Map([
  ['Stix-Core-Object', new Map([
    ['entity_type', {} as never], ['createdBy', {} as never], ['created_at', {} as never],
  ])],
]);

const parseFilters = (link: string): FilterGroup => {
  const raw = new URLSearchParams(link.split('?')[1]).get('filters');
  return JSON.parse(raw as string);
};

/**
 * `buildFiltersAndOptionsForWidgets` nests the widget's own filters into a
 * sub-group as soon as a date bound exists, so asserting on the top level alone
 * would let a filter that is still present pass for removed.
 */
const allFilters = (group: FilterGroup): Filter[] => [
  ...group.filters,
  ...(group.filterGroups ?? []).flatMap(allFilters),
];

const NO_RANGE = { startDate: null, endDate: null };

const baseInput = (overrides: Partial<DrilldownInput> = {}): DrilldownInput => ({
  perspective: 'entities',
  dataSelection: {
    perspective: 'entities',
    date_attribute: 'created_at',
    filters: { mode: 'and', filters: [{ key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' }], filterGroups: [] },
  } as never,
  range: NO_RANGE,
  interval: 'month',
  bucket: { kind: 'timeSeries', date: '2024-03-01T00:00:00.000Z' },
  filterKeysSchema: SCHEMA,
  ...overrides,
});

describe('resolveDrilldownLink', () => {
  it('targets the dedicated list and drops the redundant entity_type filter', () => {
    const link = resolveDrilldownLink(baseInput()) as string;
    expect(link.startsWith('/dashboard/arsenal/malwares?filters=')).toBe(true);
    expect(allFilters(parseFilters(link)).some((f) => f.key === 'entity_type')).toBe(false);
  });

  it('emits frontend-format filters with a string key and a generated id', () => {
    const link = resolveDrilldownLink(baseInput()) as string;
    allFilters(parseFilters(link)).forEach((f) => {
      expect(typeof f.key).toBe('string');
      expect(typeof f.id).toBe('string');
    });
  });

  it('carries the exact bucket boundaries', () => {
    const link = resolveDrilldownLink(baseInput()) as string;
    const dates = allFilters(parseFilters(link)).filter((f) => f.key === 'created_at');
    expect(dates).toHaveLength(2);
    expect(dates[0]).toMatchObject({ operator: 'gte', values: ['2024-03-01T00:00:00.000Z'] });
    expect(dates[1]).toMatchObject({ operator: 'lt', values: ['2024-04-01T00:00:00.000Z'] });
  });

  it('clamps the bucket to the range the query actually used', () => {
    const link = resolveDrilldownLink(baseInput({
      range: { startDate: '2024-03-10T00:00:00.000Z', endDate: null },
    })) as string;
    const dates = allFilters(parseFilters(link)).filter((f) => f.key === 'created_at');
    expect(dates[0]).toMatchObject({ operator: 'gte', values: ['2024-03-10T00:00:00.000Z'] });
  });

  it('keeps entity_type when the destination is the generic list', () => {
    const input = baseInput({
      dataSelection: {
        perspective: 'entities',
        date_attribute: 'created_at',
        filters: { mode: 'and', filters: [{ key: 'entity_type', values: ['Malware', 'Tool'], operator: 'eq', mode: 'or' }], filterGroups: [] },
      } as never,
    });
    const link = resolveDrilldownLink(input) as string;
    expect(link.startsWith('/dashboard/data/entities?filters=')).toBe(true);
    expect(allFilters(parseFilters(link)).some((f) => f.key === 'entity_type')).toBe(true);
  });

  it('adds the distribution value filter', () => {
    const input = baseInput({
      dataSelection: { perspective: 'entities', date_attribute: 'created_at', attribute: 'created-by.internal_id', filters: null } as never,
      bucket: { kind: 'distribution', rawValue: 'author-1', entityId: 'author-1' },
    });
    const link = resolveDrilldownLink(input) as string;
    expect(allFilters(parseFilters(link))).toContainEqual(
      expect.objectContaining({ key: 'createdBy', values: ['author-1'], operator: 'eq' }),
    );
  });

  it('applies the widget range to a distribution bucket', () => {
    const input = baseInput({
      dataSelection: { perspective: 'entities', date_attribute: 'created_at', attribute: 'created-by.internal_id', filters: null } as never,
      bucket: { kind: 'distribution', rawValue: 'author-1', entityId: 'author-1' },
      range: { startDate: '2024-01-01T00:00:00.000Z', endDate: '2024-06-01T00:00:00.000Z' },
    });
    const dates = allFilters(parseFilters(resolveDrilldownLink(input) as string)).filter((f) => f.key === 'created_at');
    expect(dates).toHaveLength(2);
    expect(dates.map((f) => f.operator)).toEqual(['gt', 'lt']);
  });

  it('never merges the bucket filter into a widget filter group using the or mode', () => {
    const input = baseInput({
      dataSelection: {
        perspective: 'entities',
        date_attribute: 'created_at',
        filters: {
          mode: 'or',
          filters: [
            { key: 'objectLabel', values: ['l-1'], operator: 'eq', mode: 'or' },
            { key: 'createdBy', values: ['a-1'], operator: 'eq', mode: 'or' },
          ],
          filterGroups: [],
        },
      } as never,
    });
    const group = parseFilters(resolveDrilldownLink(input) as string);
    // The bucket bounds must restrict the widget filters, never widen them.
    expect(group.mode).toEqual('and');
    expect(group.filters.map((f) => f.key)).toEqual(['created_at', 'created_at']);
    expect(group.filterGroups[0].mode).toEqual('or');
  });

  it('omits date filters for a total bucket without a configured range', () => {
    const input = baseInput({ bucket: { kind: 'total' }, interval: null });
    const link = resolveDrilldownLink(input) as string;
    expect(allFilters(parseFilters(link)).some((f) => f.key === 'created_at')).toBe(false);
  });

  it('uses the widget range with an exclusive lower bound for a total bucket', () => {
    const input = baseInput({
      bucket: { kind: 'total' },
      interval: null,
      range: { startDate: '2024-01-01T00:00:00.000Z', endDate: null },
    });
    const link = resolveDrilldownLink(input) as string;
    const dates = allFilters(parseFilters(link)).filter((f) => f.key === 'created_at');
    expect(dates).toHaveLength(1);
    expect(dates[0]).toMatchObject({ operator: 'gt' });
  });

  // `stixCoreObjectsNumber` computes `total` with `R.dissoc('endDate', args)`
  // (stixCoreObject.js:465), so an upper bound here would open a shorter list.
  it('ignores the end date for a total bucket, as the number query does', () => {
    const input = baseInput({
      bucket: { kind: 'total' },
      interval: null,
      range: { startDate: '2024-01-01T00:00:00.000Z', endDate: '2024-06-01T00:00:00.000Z' },
    });
    const dates = allFilters(parseFilters(resolveDrilldownLink(input) as string)).filter((f) => f.key === 'created_at');
    expect(dates).toHaveLength(1);
    expect(dates[0]).toMatchObject({ operator: 'gt', values: ['2024-01-01T00:00:00.000Z'] });
  });

  it('returns null when the widget uses dynamicFrom', () => {
    const input = baseInput({
      dataSelection: {
        perspective: 'entities',
        date_attribute: 'created_at',
        filters: { mode: 'and', filters: [{ key: 'dynamicFrom', values: ['x'], mode: 'or' }], filterGroups: [] },
      } as never,
    });
    expect(resolveDrilldownLink(input)).toBeNull();
  });

  it('returns null when the distribution attribute is unmapped', () => {
    const input = baseInput({
      dataSelection: { perspective: 'entities', date_attribute: 'created_at', attribute: 'custom_field', filters: null } as never,
      bucket: { kind: 'distribution', rawValue: 'x', entityId: null },
    });
    expect(resolveDrilldownLink(input)).toBeNull();
  });

  it('returns null when the interval is unsupported', () => {
    expect(resolveDrilldownLink(baseInput({ interval: 'fortnight' }))).toBeNull();
  });

  it('returns null for an unknown perspective', () => {
    expect(resolveDrilldownLink(baseInput({ perspective: '%future added value' as never }))).toBeNull();
  });
});
