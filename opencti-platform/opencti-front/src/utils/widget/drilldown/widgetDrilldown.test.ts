import { describe, expect, it } from 'vitest';
import moment from 'moment';
import { resolveDrilldownLink } from './widgetDrilldown';
import type { DrilldownInput, FilterGroup } from './widgetDrilldown-types';
import type { Filter } from '../../filters/filtersHelpers-types';

// Mirrors the real schema: `entity_type` is deleted from every concrete
// non-relationship type and only survives on the abstract ones and on
// relationships (`filterKeysSchema.ts:543-545`).
const SCHEMA = new Map([
  ['Stix-Domain-Object', new Map([
    ['entity_type', {} as never], ['createdBy', {} as never], ['created_at', {} as never],
    ['objectLabel', {} as never],
  ])],
  ['Stix-Cyber-Observable', new Map([
    ['entity_type', {} as never], ['createdBy', {} as never], ['created_at', {} as never],
  ])],
  ['Malware', new Map([['createdBy', {} as never], ['created_at', {} as never]])],
  ['IPv4-Addr', new Map([['createdBy', {} as never], ['created_at', {} as never]])],
  ['stix-core-relationship', new Map([
    ['entity_type', {} as never], ['relationship_type', {} as never], ['createdBy', {} as never],
    ['created_at', {} as never], ['fromId', {} as never], ['toId', {} as never],
    ['fromTypes', {} as never], ['toTypes', {} as never],
  ])],
  ['History', new Map([
    ['entity_type', {} as never], ['createdBy', {} as never], ['objectLabel', {} as never],
    ['created_at', {} as never], ['timestamp', {} as never],
  ])],
]);

const SDO_TYPES = ['Malware', 'Tool', 'Report', 'Intrusion-Set', 'Campaign'];

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

/**
 * The bucket instant the API would return for that calendar period start, in
 * the timezone of the process. `fillTimeSeries` builds period starts in the
 * browser offset then converts to UTC, so a hardcoded UTC midnight describes a
 * bucket no browser west of UTC can emit -- and the assertion below would then
 * read a neighbouring day. See `widgetDrilldownFilters.test.ts`.
 */
const apiBucketDate = (periodStart: string) => moment(periodStart, 'YYYY-MM-DD').utc().toISOString();

const baseInput = (overrides: Partial<DrilldownInput> = {}): DrilldownInput => ({
  perspective: 'entities',
  dataSelection: {
    perspective: 'entities',
    date_attribute: 'created_at',
    filters: { mode: 'and', filters: [{ key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' }], filterGroups: [] },
  } as never,
  range: NO_RANGE,
  configRange: NO_RANGE,
  interval: 'month',
  bucket: { kind: 'timeSeries', date: apiBucketDate('2024-03-01') },
  filterKeysSchema: SCHEMA,
  subtypesByAbstractType: {
    'Stix-Domain-Object': SDO_TYPES,
    'Stix-Cyber-Observable': ['IPv4-Addr', 'Url'],
    'stix-core-relationship': ['targets', 'uses', 'attributed-to'],
  },
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
      dataSelection: {
        perspective: 'entities',
        date_attribute: 'created_at',
        attribute: 'created-by.internal_id',
        filters: { mode: 'and', filters: [{ key: 'entity_type', values: ['Malware', 'Report'], operator: 'eq', mode: 'or' }], filterGroups: [] },
      } as never,
      bucket: { kind: 'distribution', rawValue: 'author-1', entityId: 'author-1' },
    });
    const link = resolveDrilldownLink(input) as string;
    expect(allFilters(parseFilters(link))).toContainEqual(
      expect.objectContaining({ key: 'createdBy', values: ['author-1'], operator: 'eq' }),
    );
  });

  it('applies the dashboard range to a distribution bucket', () => {
    const input = baseInput({
      dataSelection: {
        perspective: 'entities',
        date_attribute: 'created_at',
        attribute: 'created-by.internal_id',
        filters: { mode: 'and', filters: [{ key: 'entity_type', values: ['Malware', 'Report'], operator: 'eq', mode: 'or' }], filterGroups: [] },
      } as never,
      bucket: { kind: 'distribution', rawValue: 'author-1', entityId: 'author-1' },
      configRange: { startDate: '2024-01-01T00:00:00.000Z', endDate: '2024-06-01T00:00:00.000Z' },
    });
    const dates = allFilters(parseFilters(resolveDrilldownLink(input) as string)).filter((f) => f.key === 'created_at');
    expect(dates).toHaveLength(2);
    expect(dates.map((f) => f.operator)).toEqual(['gt', 'lt']);
  });

  // Expressed on the audit log, the one destination holding exactly what its
  // widget counts, so the assertion is about nesting and nothing else.
  it('never merges the bucket filter into a widget filter group using the or mode', () => {
    const input = baseInput({
      perspective: 'audits',
      dataSelection: {
        perspective: 'audits',
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

  it('uses the dashboard range with an exclusive lower bound for a total bucket', () => {
    const input = baseInput({
      bucket: { kind: 'total' },
      interval: null,
      configRange: { startDate: '2024-01-01T00:00:00.000Z', endDate: null },
    });
    const link = resolveDrilldownLink(input) as string;
    const dates = allFilters(parseFilters(link)).filter((f) => f.key === 'created_at');
    expect(dates).toHaveLength(1);
    expect(dates[0]).toMatchObject({ operator: 'gt' });
  });

  // `stixCoreObjectsNumber` computes `total` with `R.dissoc('endDate', args)`
  // (stixCoreObject.js:465), but the argument it drops is the 24h variation
  // window, never the dashboard bound -- which sits in the filters and did bound
  // the displayed number.
  it('keeps the dashboard end date on a total bucket', () => {
    const input = baseInput({
      bucket: { kind: 'total' },
      interval: null,
      configRange: { startDate: '2024-01-01T00:00:00.000Z', endDate: '2024-06-01T00:00:00.000Z' },
    });
    const dates = allFilters(parseFilters(resolveDrilldownLink(input) as string)).filter((f) => f.key === 'created_at');
    expect(dates.map((f) => f.operator)).toEqual(['gt', 'lt']);
    expect(dates[1].values).toEqual(['2024-06-01T00:00:00.000Z']);
  });

  // The container sends `dayAgo()` as `endDate` to feed the 24h variation; the
  // number itself is bounded by the filters. Reading the link bounds back from
  // the variables would cut the list at yesterday.
  it('ignores the sent variables range on a total bucket', () => {
    const input = baseInput({
      bucket: { kind: 'total' },
      interval: null,
      range: { startDate: null, endDate: '2024-09-30T00:00:00.000Z' },
      configRange: NO_RANGE,
    });
    const dates = allFilters(parseFilters(resolveDrilldownLink(input) as string)).filter((f) => f.key === 'created_at');
    expect(dates).toHaveLength(0);
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

describe('resolveDrilldownLink — distinct (unique) selections', () => {
  const distinct = (bucket: DrilldownInput['bucket']) => resolveDrilldownLink(baseInput({
    bucket,
    dataSelection: {
      perspective: 'audits',
      date_attribute: 'timestamp',
      attribute: 'user_id',
      unique: true,
      filters: { mode: 'and', filters: [], filterGroups: [] },
    } as never,
    perspective: 'audits',
  }));

  it('refuses a distinct total: it counts values, not documents', () => {
    expect(distinct({ kind: 'total' })).toBeNull();
  });

  it('refuses a distinct time-series bucket', () => {
    expect(distinct({ kind: 'timeSeries', date: apiBucketDate('2024-03-01') })).toBeNull();
  });

  it('still resolves the same audit selection when distinct is off', () => {
    const link = resolveDrilldownLink(baseInput({
      bucket: { kind: 'total' },
      perspective: 'audits',
      dataSelection: {
        perspective: 'audits',
        date_attribute: 'timestamp',
        attribute: 'user_id',
        unique: false,
        filters: { mode: 'and', filters: [], filterGroups: [] },
      } as never,
    }));
    expect(link).not.toBeNull();
    expect((link as string).startsWith('/dashboard/audits?filters=')).toBe(true);
  });
});

/**
 * End-to-end shape of the link a Home dashboard bar chart produces: perspective
 * `relationships`, aggregation on the source side of each relationship.
 */
describe('resolveDrilldownLink on a relationship connection bucket', () => {
  const RELATIONSHIP_SCHEMA = new Map([
    ['stix-core-relationship', new Map([
      ['fromId', {} as never], ['toId', {} as never], ['fromTypes', {} as never],
      ['entity_type', {} as never], ['created_at', {} as never],
    ])],
  ]);

  const relationshipInput = (isTo: boolean | null) => baseInput({
    perspective: 'relationships',
    filterKeysSchema: RELATIONSHIP_SCHEMA,
    bucket: { kind: 'distribution', rawValue: 'threat-1', entityId: 'threat-1' },
    dataSelection: {
      perspective: 'relationships',
      attribute: 'internal_id',
      date_attribute: 'created_at',
      isTo,
      filters: {
        mode: 'and',
        filters: [{ key: 'entity_type', values: ['stix-core-relationship'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    } as never,
  });

  it('opens the relationships list restricted to the counted side', () => {
    const link = resolveDrilldownLink(relationshipInput(false)) as string;
    expect(link.startsWith('/dashboard/data/relationships?filters=')).toBe(true);
    const fromId = allFilters(parseFilters(link)).find((f) => f.key === 'fromId');
    expect(fromId?.values).toEqual(['threat-1']);
  });

  it('keeps the widget entity_type filter, since the destination is generic', () => {
    const link = resolveDrilldownLink(relationshipInput(false)) as string;
    expect(allFilters(parseFilters(link)).some((f) => f.key === 'entity_type')).toBe(true);
  });

  it('stays inert when the aggregation counted both sides', () => {
    expect(resolveDrilldownLink(relationshipInput(null))).toBeNull();
  });
});

/**
 * The relationships list pins `stix-core-relationship` (Relationships.tsx:281),
 * while a widget aggregates over `stix-relationship` unless its own filters
 * narrow that down (stixRelationship.js:36-38). A widget counting refs or
 * sightings therefore has no list able to show the same population.
 */
describe('resolveDrilldownLink on a relationship population the list cannot hold', () => {
  const RELATIONSHIP_SCHEMA = new Map([
    ['stix-core-relationship', new Map([
      ['toId', {} as never], ['toTypes', {} as never], ['entity_type', {} as never],
      ['relationship_type', {} as never], ['created_at', {} as never],
    ])],
  ]);

  const labelsWidget = (filters: { key: string; values: string[]; operator: string; mode: string }[]) => baseInput({
    perspective: 'relationships',
    filterKeysSchema: RELATIONSHIP_SCHEMA,
    bucket: { kind: 'distribution', rawValue: 'label-1', entityId: 'label-1' },
    dataSelection: {
      perspective: 'relationships',
      attribute: 'internal_id',
      date_attribute: 'created_at',
      isTo: true,
      filters: { mode: 'and', filters, filterGroups: [] },
    } as never,
  });

  // The exact shape of the "Most active labels" widget: it counts `object-label`
  // ref relationships, none of which appear on the relationships list.
  it('refuses a widget scoped only by the type of its endpoints', () => {
    expect(resolveDrilldownLink(labelsWidget([
      { key: 'toTypes', values: ['Label'], operator: 'eq', mode: 'or' },
    ]))).toBeNull();
  });

  it('refuses a widget spanning every stix relationship', () => {
    expect(resolveDrilldownLink(labelsWidget([
      { key: 'entity_type', values: ['stix-relationship'], operator: 'eq', mode: 'or' },
    ]))).toBeNull();
  });

  it('refuses sightings, which the list does not hold either', () => {
    expect(resolveDrilldownLink(labelsWidget([
      { key: 'entity_type', values: ['stix-sighting-relationship'], operator: 'eq', mode: 'or' },
    ]))).toBeNull();
  });

  it('accepts the abstract stix-core-relationship type', () => {
    expect(resolveDrilldownLink(labelsWidget([
      { key: 'entity_type', values: ['stix-core-relationship'], operator: 'eq', mode: 'or' },
    ]))).not.toBeNull();
  });

  it('accepts concrete core relationship types', () => {
    expect(resolveDrilldownLink(labelsWidget([
      { key: 'relationship_type', values: ['targets', 'uses'], operator: 'eq', mode: 'or' },
    ]))).not.toBeNull();
  });

  it('refuses a set mixing a core type with an uncovered one', () => {
    expect(resolveDrilldownLink(labelsWidget([
      { key: 'entity_type', values: ['targets', 'stix-sighting-relationship'], operator: 'eq', mode: 'or' },
    ]))).toBeNull();
  });

  it('refuses an `or` mode, where a sibling filter re-widens the population', () => {
    const input = labelsWidget([
      { key: 'entity_type', values: ['stix-core-relationship'], operator: 'eq', mode: 'or' },
      { key: 'toTypes', values: ['Label'], operator: 'eq', mode: 'or' },
    ]);
    (input.dataSelection as { filters: { mode: string } }).filters.mode = 'or';
    expect(resolveDrilldownLink(input)).toBeNull();
  });

  it('refuses a negated scope, which widens instead of narrowing', () => {
    expect(resolveDrilldownLink(labelsWidget([
      { key: 'entity_type', values: ['stix-core-relationship'], operator: 'not_eq', mode: 'or' },
    ]))).toBeNull();
  });
});

/**
 * `entity_type` is not a filter key of any concrete type (`filterKeysSchema.ts:545`),
 * so checking the key against the *widget* types made every entity_type
 * distribution inert. The question only makes sense at the destination, which
 * pins abstract types -- and for a single type, the bucket names the dedicated
 * list itself.
 */
describe('resolveDrilldownLink on an entity_type distribution', () => {
  const onEntityType = (values: string[], bucketValue: string) => baseInput({
    dataSelection: {
      perspective: 'entities',
      date_attribute: 'created_at',
      attribute: 'entity_type',
      filters: { mode: 'and', filters: [{ key: 'entity_type', values, operator: 'eq', mode: 'or' }], filterGroups: [] },
    } as never,
    bucket: { kind: 'distribution', rawValue: bucketValue, entityId: null },
  });

  it('opens the dedicated list of the clicked type', () => {
    const link = resolveDrilldownLink(onEntityType(['Malware', 'Report'], 'Malware')) as string;
    expect(link.startsWith('/dashboard/arsenal/malwares?filters=')).toBe(true);
    // The destination pins Malware itself, so repeating it would be dropped anyway.
    expect(allFilters(parseFilters(link)).some((f) => f.key === 'entity_type')).toBe(false);
  });

  // The API pascalizes the bucket label (`engine.ts:3402`), so an observable
  // widget really reports `Ipv4-Addr`. Filtering on that spelling would open an
  // empty list next to a non-zero bar.
  it('opens the observables list with the clicked type kept, that list being shared', () => {
    const link = resolveDrilldownLink(onEntityType(['Malware', 'IPv4-Addr'], 'Ipv4-Addr')) as string;
    expect(link.startsWith('/dashboard/observations/observables?filters=')).toBe(true);
    expect(allFilters(parseFilters(link))).toContainEqual(
      expect.objectContaining({ key: 'entity_type', values: ['IPv4-Addr'] }),
    );
  });

  it('opens the dedicated list of a pascalized type too', () => {
    const link = resolveDrilldownLink(onEntityType(['Malware', 'Report'], 'malware')) as string;
    expect(link.startsWith('/dashboard/arsenal/malwares?filters=')).toBe(true);
  });

  it('works without any widget type restriction, the bucket pinning the type', () => {
    const input = baseInput({
      dataSelection: { perspective: 'entities', date_attribute: 'created_at', attribute: 'entity_type', filters: null } as never,
      bucket: { kind: 'distribution', rawValue: 'Malware', entityId: null },
    });
    expect((resolveDrilldownLink(input) as string).startsWith('/dashboard/arsenal/malwares?')).toBe(true);
  });

  it('refuses a type the platform does not know', () => {
    expect(resolveDrilldownLink(onEntityType(['Malware', 'Report'], 'Some-Custom-Type'))).toBeNull();
  });
});

/**
 * The entities list queries `stixDomainObjects` (`Entities.tsx:45`) while the
 * widget aggregates every `Stix-Core-Object`: without a type restriction the
 * observables counted by the widget would be missing from the list.
 */
describe('resolveDrilldownLink on an entity population the list cannot hold', () => {
  const byAuthor = (filters: FilterGroup | null) => baseInput({
    dataSelection: {
      perspective: 'entities',
      date_attribute: 'created_at',
      attribute: 'created-by.internal_id',
      filters,
    } as never,
    bucket: { kind: 'distribution', rawValue: 'author-1', entityId: 'author-1' },
  });

  it('refuses an unrestricted widget', () => {
    expect(resolveDrilldownLink(byAuthor(null))).toBeNull();
  });

  it('refuses a widget spanning observables', () => {
    expect(resolveDrilldownLink(byAuthor({
      mode: 'and',
      filters: [{ key: 'entity_type', values: ['Malware', 'IPv4-Addr'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    }))).toBeNull();
  });

  it('accepts a widget restricted to stix domain objects', () => {
    expect(resolveDrilldownLink(byAuthor({
      mode: 'and',
      filters: [{ key: 'entity_type', values: ['Malware', 'Report'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    }))).not.toBeNull();
  });

  it('accepts the abstract Stix-Domain-Object type itself', () => {
    expect(resolveDrilldownLink(byAuthor({
      mode: 'and',
      filters: [{ key: 'entity_type', values: ['Stix-Domain-Object'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    }))).not.toBeNull();
  });
});

/**
 * Four ways a link could promise a number the destination will not reproduce.
 * Each one is a silent widening: nothing errors, the list simply shows more.
 */
describe('resolveDrilldownLink fail-closed guards', () => {
  const orWidget = (filters: FilterGroup) => baseInput({
    bucket: { kind: 'total' },
    interval: null,
    dataSelection: { perspective: 'entities', date_attribute: 'created_at', filters } as never,
  });

  // `entity_type: Malware OR createdBy: a-1` counts malwares *and* everything
  // that author wrote, which the malwares list cannot show.
  it('refuses a dedicated list when the type filter sits under an or mode', () => {
    expect(resolveDrilldownLink(orWidget({
      mode: 'or',
      filters: [
        { key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' },
        { key: 'createdBy', values: ['a-1'], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    }))).toBeNull();
  });

  // Same widening, carried by a sub-group instead of a sibling filter.
  it('refuses a dedicated list when an or mode carries a sub-group', () => {
    expect(resolveDrilldownLink(orWidget({
      mode: 'or',
      filters: [{ key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' }],
      filterGroups: [{
        mode: 'and',
        filters: [{ key: 'createdBy', values: ['a-1'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      }],
    }))).toBeNull();
  });

  // `dynamicFrom` / `dynamicTo` are sibling sub-queries of the data selection,
  // not filters, so they never reach `assertRepresentable` -- and no list URL can
  // carry them.
  it.each([
    ['dynamicFrom', { dynamicFrom: { mode: 'and', filters: [{ key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' }], filterGroups: [] } }],
    ['dynamicTo', { dynamicTo: { mode: 'and', filters: [{ key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' }], filterGroups: [] } }],
    ['dynamicFrom_id', { dynamicFrom_id: 'saved-filter-1' }],
    ['dynamicTo_id', { dynamicTo_id: 'saved-filter-1' }],
  ])('refuses a selection restricted by %s', (_name, extra) => {
    expect(resolveDrilldownLink(baseInput({
      bucket: { kind: 'total' },
      interval: null,
      dataSelection: {
        perspective: 'entities',
        date_attribute: 'created_at',
        filters: { mode: 'and', filters: [{ key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' }], filterGroups: [] },
        ...extra,
      } as never,
    }))).toBeNull();
  });

  it('ignores empty dynamic sub-queries', () => {
    expect(resolveDrilldownLink(baseInput({
      bucket: { kind: 'total' },
      interval: null,
      dataSelection: {
        perspective: 'entities',
        date_attribute: 'created_at',
        filters: { mode: 'and', filters: [{ key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' }], filterGroups: [] },
        dynamicFrom: { mode: 'and', filters: [], filterGroups: [] },
        dynamicTo: { mode: 'and', filters: [], filterGroups: [] },
      } as never,
    }))).not.toBeNull();
  });

  // The malwares list would drop a key its schema does not hold, and show every
  // malware instead of the counted subset.
  it.each([
    ['at the top level', {
      mode: 'and',
      filters: [
        { key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' },
        { key: 'x_opencti_workflow_id', values: ['w-1'], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    }],
    ['inside a sub-group', {
      mode: 'and',
      filters: [{ key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' }],
      filterGroups: [{
        mode: 'and',
        filters: [{ key: 'x_opencti_workflow_id', values: ['w-1'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      }],
    }],
  ])('refuses a widget filter the destination would drop, %s', (_name, filters) => {
    expect(resolveDrilldownLink(orWidget(filters as FilterGroup))).toBeNull();
  });

  it('accepts widget filters the destination supports', () => {
    expect(resolveDrilldownLink(orWidget({
      mode: 'and',
      filters: [
        { key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' },
        { key: 'createdBy', values: ['a-1'], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    }))).not.toBeNull();
  });
});
