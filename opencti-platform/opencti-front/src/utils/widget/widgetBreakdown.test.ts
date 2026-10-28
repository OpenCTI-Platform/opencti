import { describe, expect, it } from 'vitest';
import type { Widget } from './widget';
import type { FilterDefinition } from '../hooks/useAuth';
import type { FilterGroup } from '../filters/filtersHelpers-types';
import { daysAgo, monthsAgo } from '../Time';
import {
  BREAKDOWN_ALLOWED_REFS,
  coarsenSeriesForRendering,
  getBreakdownEntityTypes,
  getBreakdownDefaultStartDate,
  getBreakdownFieldOptions,
  getBreakdownTickAmount,
  getRenderedBarsBudget,
  getRenderedPointsBudget,
  getWidgetBreakdownLimit,
  getWidgetBreakdownOrder,
  getWidgetBreakdownOther,
  hasWidgetBreakdown,
  isBreakdownFieldSupported,
  isBreakdownTypeField,
  isWidgetBreakdownActive,
  isWidgetBreakdownEligible,
  MAX_RENDERED_BARS,
  MIN_RENDERED_BARS,
  nextBreakdownChartWidth,
} from './widgetBreakdown';

const workspace = { kind: 'workspace' } as const;

const makeWidget = (overrides: Partial<Widget> = {}, entityTypes: string[] = ['Report']): Widget => ({
  id: 'widget',
  type: 'vertical-bar',
  perspective: 'entities',
  dataSelection: [{
    filters: {
      mode: 'and',
      filters: [{ key: 'entity_type', values: entityTypes, operator: 'eq', mode: 'or' }],
      filterGroups: [],
    },
  }],
  parameters: { breakdownBy: 'entity_type' },
  ...overrides,
} as unknown as Widget);

const makeRelationshipsWidget = (overrides: Partial<Widget> = {}, relationshipTypes: string[] = ['targets']): Widget => ({
  id: 'widget',
  type: 'line',
  perspective: 'relationships',
  dataSelection: [{
    perspective: 'relationships',
    filters: {
      mode: 'and',
      filters: [{ key: 'relationship_type', values: relationshipTypes, operator: 'eq', mode: 'or' }],
      filterGroups: [],
    },
    dynamicFrom: { mode: 'and', filters: [{ key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' }], filterGroups: [] },
  }],
  parameters: { breakdownBy: 'toTypes' },
  ...overrides,
} as unknown as Widget);

// One point per UTC day, starting on a given date
const daily = (start: string, values: number[]) => values.map((y, i) => {
  const x = new Date(start);
  x.setUTCDate(x.getUTCDate() + i);
  return { x, y };
});

describe('widget breakdown eligibility', () => {
  it('accepts every entities time series visualization of a workspace dashboard', () => {
    ['vertical-bar', 'line', 'area', 'heatmap'].forEach((type) => {
      expect(isWidgetBreakdownActive(makeWidget({ type }), workspace)).toBe(true);
    });
  });

  it('accepts every relationships time series visualization of a workspace dashboard', () => {
    ['vertical-bar', 'line', 'area', 'heatmap'].forEach((type) => {
      expect(isWidgetBreakdownActive(makeRelationshipsWidget({ type }), workspace)).toBe(true);
    });
    // Older datasets carry no perspective of their own
    const withoutDatasetPerspective = makeRelationshipsWidget();
    withoutDatasetPerspective.dataSelection = [{ ...withoutDatasetPerspective.dataSelection[0], perspective: undefined }];
    expect(isWidgetBreakdownEligible(withoutDatasetPerspective, workspace)).toBe(true);
  });

  it('rejects the relationships widgets that cannot be broken down', () => {
    expect(isWidgetBreakdownEligible(makeRelationshipsWidget({ type: 'donut' }), workspace)).toBe(false);
    const widget = makeRelationshipsWidget();
    expect(isWidgetBreakdownEligible({ ...widget, dataSelection: [...widget.dataSelection, ...widget.dataSelection] }, workspace)).toBe(false);
    // A relationships widget can hold an entities dataset: it is not a dataset of relationships
    expect(isWidgetBreakdownEligible({ ...widget, dataSelection: [{ ...widget.dataSelection[0], perspective: 'entities' }] }, workspace)).toBe(false);
    const customView = { kind: 'custom-view' as const, customViewTargetEntityType: 'Report' };
    expect(isWidgetBreakdownActive(widget, customView)).toBe(false);
    expect(hasWidgetBreakdown(widget)).toBe(true);
  });

  it('rejects other visualizations, perspectives, several datasets and drafts', () => {
    expect(isWidgetBreakdownEligible(makeWidget({ type: 'donut' }), workspace)).toBe(false);
    expect(isWidgetBreakdownEligible(makeWidget({ perspective: 'audits' }), workspace)).toBe(false);
    expect(isWidgetBreakdownEligible(makeWidget({ perspective: null }), workspace)).toBe(false);
    const widget = makeWidget();
    expect(isWidgetBreakdownEligible({ ...widget, dataSelection: [...widget.dataSelection, ...widget.dataSelection] }, workspace)).toBe(false);
    expect(isWidgetBreakdownEligible(makeWidget({}, ['DraftWorkspace']), workspace)).toBe(false);
  });

  it('only renders breakdowns in workspace dashboards', () => {
    const customView = { kind: 'custom-view' as const, customViewTargetEntityType: 'Report' };
    expect(isWidgetBreakdownActive(makeWidget(), customView)).toBe(false);
    expect(isWidgetBreakdownActive(makeWidget(), undefined)).toBe(false);
    // ...but still knows the widget is broken down, to refuse it elsewhere
    expect(hasWidgetBreakdown(makeWidget())).toBe(true);
  });

  it('needs a breakdown field', () => {
    expect(isWidgetBreakdownActive(makeWidget({ parameters: { breakdownBy: null } }), workspace)).toBe(false);
  });

  it('defaults the number of series', () => {
    expect(getWidgetBreakdownLimit({})).toEqual(10);
    expect(getWidgetBreakdownLimit({ breakdownLimit: 50 })).toEqual(50);
  });

  it('orders by highest values and leaves the other series out by default', () => {
    expect(getWidgetBreakdownOrder({})).toEqual('desc');
    expect(getWidgetBreakdownOrder({ breakdownOrder: null })).toEqual('desc');
    expect(getWidgetBreakdownOrder({ breakdownOrder: 'asc' })).toEqual('asc');
    expect(getWidgetBreakdownOther(undefined)).toBe(false);
    expect(getWidgetBreakdownOther({ breakdownOther: null })).toBe(false);
    expect(getWidgetBreakdownOther({ breakdownOther: true })).toBe(true);
  });
});

describe('isBreakdownTypeField', () => {
  it('knows the fields whose values are entity or relationship types', () => {
    ['entity_type', 'relationship_type', 'fromTypes', 'toTypes'].forEach((field) => expect(isBreakdownTypeField(field)).toBe(true));
    ['objectLabel', 'creator_id', null, undefined].forEach((field) => expect(isBreakdownTypeField(field)).toBe(false));
  });
});

describe('getBreakdownDefaultStartDate', () => {
  it('only looks back 30 days for a daily breakdown', () => {
    expect(getBreakdownDefaultStartDate('day')).toEqual(daysAgo(30));
  });

  it('looks back 12 months for the other intervals', () => {
    ['week', 'month', 'quarter', 'year'].forEach((interval) => {
      expect(getBreakdownDefaultStartDate(interval)).toEqual(monthsAgo(12));
    });
  });
});

describe('getBreakdownEntityTypes', () => {
  const group = (filters: FilterGroup['filters'], mode: 'and' | 'or' = 'and'): FilterGroup => ({ mode, filters, filterGroups: [] });

  it('reads the entity types the filters restrict to', () => {
    expect(getBreakdownEntityTypes(group([
      { key: 'entity_type', values: ['Report', 'Grouping'], operator: 'eq', mode: 'or' },
      { key: 'objectLabel', values: ['label-id'], operator: 'eq', mode: 'or' },
    ]))).toEqual(['Report', 'Grouping']);
  });

  it('returns no type when the filters do not restrict it for sure', () => {
    expect(getBreakdownEntityTypes(undefined)).toEqual([]);
    expect(getBreakdownEntityTypes(group([{ key: 'objectLabel', values: ['label-id'], operator: 'eq', mode: 'or' }]))).toEqual([]);
    expect(getBreakdownEntityTypes(group([{ key: 'entity_type', values: ['Report'], operator: 'not_eq', mode: 'or' }]))).toEqual([]);
    // "type = Report OR label = A" can also return other types
    expect(getBreakdownEntityTypes(group([
      { key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' },
      { key: 'objectLabel', values: ['label-id'], operator: 'eq', mode: 'or' },
    ], 'or'))).toEqual([]);
  });

  it('reads the relationship types of a relationships dataset', () => {
    const filters = group([
      { key: 'relationship_type', values: ['targets', 'uses'], operator: 'eq', mode: 'or' },
      { key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' },
    ]);
    expect(getBreakdownEntityTypes(filters, 'relationships')).toEqual(['targets', 'uses']);
    expect(getBreakdownEntityTypes(filters)).toEqual(['Report']);
    expect(getBreakdownEntityTypes(group([{ key: 'relationship_type', values: ['uses'], operator: 'not_eq', mode: 'or' }]), 'relationships')).toEqual([]);
    expect(getBreakdownEntityTypes(filters, 'audits')).toEqual([]);
  });
});

describe('getBreakdownFieldOptions', () => {
  const definition = (filterKey: string, type: string, label: string, subEntityTypes: string[]): FilterDefinition => ({
    filterKey, type, label, multiple: true, subEntityTypes, elementsForFilterValuesSearch: [],
  });
  const schema = new Map<string, Map<string, FilterDefinition>>([
    ['Report', new Map([
      ['entity_type', definition('entity_type', 'string', 'Entity type', ['Report'])],
      ['createdBy', definition('createdBy', 'id', 'Author', ['Report'])],
      ['objectLabel', definition('objectLabel', 'id', 'Label', ['Report'])],
      ['report_types', definition('report_types', 'vocabulary', 'Report types', ['Report'])],
      ['name', definition('name', 'string', 'Name', ['Report'])],
      ['objects', definition('objects', 'id', 'Contains', ['Report'])],
      ['externalReferences', definition('externalReferences', 'id', 'External reference', ['Report'])],
      ['killChainPhases', definition('killChainPhases', 'id', 'Kill chain phase', ['Report'])],
      ['published', definition('published', 'date', 'Publication date', ['Report'])],
      ['computed_reliability', definition('computed_reliability', 'vocabulary', 'Reliability', ['Report'])],
      ['draft_change.draft_operation', definition('draft_change.draft_operation', 'enum', 'Draft operation', ['Report'])],
    ])],
    ['Malware', new Map([
      ['createdBy', definition('createdBy', 'id', 'Author', ['Malware'])],
      ['objectLabel', definition('objectLabel', 'id', 'Label', ['Malware'])],
      ['malware_types', definition('malware_types', 'vocabulary', 'Malware types', ['Malware'])],
    ])],
    ['Stix-Core-Object', new Map([
      // the schema lists the entity type itself: it must be offered once
      ['entity_type', definition('entity_type', 'string', 'Entity type', ['Stix-Core-Object', 'Report', 'Malware'])],
      ['createdBy', definition('createdBy', 'id', 'Author', ['Stix-Core-Object', 'Report', 'Malware'])],
      // only some sub types carry report types
      ['report_types', definition('report_types', 'vocabulary', 'Report types', ['Report'])],
    ])],
  ]);
  const keys = (entityTypes: string[]) => getBreakdownFieldOptions(schema, entityTypes).map(({ key }) => key);

  it('offers every field of a single type that can be broken down', () => {
    expect(keys(['Report'])).toEqual(['createdBy', 'objectLabel', 'report_types']);
  });

  it('only offers the allowed references, vocabularies and enums', () => {
    const options = keys(['Report']);
    BREAKDOWN_ALLOWED_REFS.forEach((key) => {
      if (schema.get('Report')?.has(key)) expect(options).toContain(key);
    });
    expect(options).toContain('report_types');
    ['objects', 'externalReferences', 'killChainPhases'].forEach((key) => expect(options).not.toContain(key));
  });

  it('offers the fields shared by several types, and the entity type', () => {
    expect(keys(['Report', 'Malware'])).toEqual(['createdBy', 'entity_type', 'objectLabel']);
  });

  it('offers the fields of the abstract type without type filter', () => {
    expect(keys([])).toEqual(['createdBy', 'entity_type']);
  });

  it('does not offer the custom fields, which the API cannot break down', () => {
    const withCustomField = new Map(schema);
    withCustomField.set('Report', new Map([
      ...(schema.get('Report') ?? new Map()),
      ['x_opencti_cf_priority', definition('x_opencti_cf_priority', 'enum', 'Priority', ['Report'])],
    ]));
    expect(getBreakdownFieldOptions(withCustomField, ['Report']).map(({ key }) => key)).toEqual(['createdBy', 'objectLabel', 'report_types']);
  });

  describe('relationships', () => {
    const relationshipsSchema = new Map<string, Map<string, FilterDefinition>>([
      ['stix-relationship', new Map([
        ['relationship_type', definition('relationship_type', 'string', 'Relationship type', ['stix-relationship', 'targets', 'uses'])],
        ['createdBy', definition('createdBy', 'id', 'Author', ['stix-relationship', 'targets', 'uses'])],
        ['objectLabel', definition('objectLabel', 'id', 'Label', ['stix-relationship', 'targets', 'uses'])],
        ['objectMarking', definition('objectMarking', 'id', 'Marking', ['stix-relationship', 'targets', 'uses'])],
        ['creator_id', definition('creator_id', 'id', 'Creators', ['stix-relationship', 'targets', 'uses'])],
        ['externalReferences', definition('externalReferences', 'id', 'External reference', ['stix-relationship', 'targets', 'uses'])],
        ['confidence', definition('confidence', 'integer', 'Confidence', ['stix-relationship', 'targets', 'uses'])],
        ['objects', definition('objects', 'id', 'Contains', ['stix-relationship', 'targets', 'uses'])],
      ])],
      ['targets', new Map([
        ['createdBy', definition('createdBy', 'id', 'Author', ['targets'])],
        ['objectMarking', definition('objectMarking', 'id', 'Marking', ['targets'])],
        ['fromId', definition('fromId', 'id', 'Source entity', ['targets'])],
        ['toId', definition('toId', 'id', 'Target entity', ['targets'])],
        ['fromTypes', definition('fromTypes', 'string', 'Source type', ['targets'])],
        ['killChainPhases', definition('killChainPhases', 'id', 'Kill chain phase', ['targets'])],
        ['workflow_id', definition('workflow_id', 'id', 'Status', ['targets'])],
      ])],
      ['uses', new Map([
        ['createdBy', definition('createdBy', 'id', 'Author', ['uses'])],
        ['usage_types', definition('usage_types', 'vocabulary', 'Usage types', ['uses'])],
      ])],
    ]);
    const relationshipKeys = (relationshipTypes: string[]) => getBreakdownFieldOptions(relationshipsSchema, relationshipTypes, 'relationships').map(({ key }) => key);

    it('offers the fields of every relationship, their type and the types of their source and target', () => {
      expect(relationshipKeys([])).toEqual(['createdBy', 'creator_id', 'objectLabel', 'objectMarking', 'relationship_type', 'fromTypes', 'toTypes']);
    });

    it('offers the fields of a single relationship type, without the relationship type', () => {
      expect(relationshipKeys(['targets'])).toEqual(['createdBy', 'objectMarking', 'fromTypes', 'toTypes']);
      expect(relationshipKeys(['uses'])).toEqual(['createdBy', 'fromTypes', 'toTypes', 'usage_types']);
    });

    it('offers the fields shared by several relationship types', () => {
      expect(relationshipKeys(['targets', 'uses'])).toEqual(['createdBy', 'relationship_type', 'fromTypes', 'toTypes']);
    });

    it('never offers the source and target themselves, nor the fields of an unbounded cardinality', () => {
      const options = relationshipKeys(['targets']);
      ['fromId', 'toId', 'objects', 'externalReferences', 'killChainPhases', 'workflow_id', 'entity_type'].forEach((key) => expect(options).not.toContain(key));
    });

    it('labels the relationships fields', () => {
      const labels = getBreakdownFieldOptions(relationshipsSchema, [], 'relationships').map(({ label }) => label);
      expect(labels).toEqual(expect.arrayContaining(['Relationship type', 'Source type', 'Target type']));
    });

    it('checks the field of a relationships widget against its relationship types', () => {
      const supported = (breakdownBy: string, relationshipTypes?: string[]) => isBreakdownFieldSupported(
        relationshipsSchema,
        { ...makeRelationshipsWidget({}, relationshipTypes), parameters: { breakdownBy } },
      );
      expect(supported('toTypes')).toBe(true);
      expect(supported('objectMarking')).toBe(true);
      expect(supported('usage_types')).toBe(false);
      expect(supported('usage_types', ['uses'])).toBe(true);
      expect(supported('relationship_type')).toBe(false);
      expect(supported('relationship_type', ['targets', 'uses'])).toBe(true);
      // An entities field is not one of the relationships
      expect(supported('entity_type', ['targets', 'uses'])).toBe(false);
    });

    it('offers no field for a perspective that cannot be broken down', () => {
      expect(getBreakdownFieldOptions(relationshipsSchema, [], 'audits')).toEqual([]);
    });
  });

  describe('isBreakdownFieldSupported', () => {
    const supported = (breakdownBy: string, entityTypes?: string[]) => isBreakdownFieldSupported(schema, {
      ...makeWidget({}, entityTypes),
      parameters: { breakdownBy },
    });

    it('accepts a field of the entity type of the dataset', () => {
      expect(supported('createdBy', ['Report'])).toBe(true);
      expect(supported('report_types', ['Report'])).toBe(true);
    });

    it('refuses a field the entity type does not have, or that cannot be broken down', () => {
      expect(supported('report_types', ['Malware'])).toBe(false);
      expect(supported('name', ['Report'])).toBe(false);
      // a single type already is the entity type
      expect(supported('entity_type', ['Report'])).toBe(false);
    });

    it('refuses a field the abstract type has not, without type filter', () => {
      const noTypeFilter = { ...makeWidget(), dataSelection: [{ filters: undefined }], parameters: { breakdownBy: 'objectAssignee' } } as unknown as Widget;
      expect(isBreakdownFieldSupported(schema, noTypeFilter)).toBe(false);
      expect(isBreakdownFieldSupported(schema, { ...noTypeFilter, parameters: { breakdownBy: 'createdBy' } })).toBe(true);
    });

    it('accepts the entity type with several types, and only their common fields', () => {
      expect(supported('entity_type', ['Report', 'Malware'])).toBe(true);
      expect(supported('objectLabel', ['Report', 'Malware'])).toBe(true);
      expect(supported('report_types', ['Report', 'Malware'])).toBe(false);
    });

    it('refuses a widget without breakdown field', () => {
      expect(isBreakdownFieldSupported(schema, makeWidget({ parameters: { breakdownBy: null } }))).toBe(false);
    });
  });
});

describe('rendered bars budget', () => {
  it('follows the width, within the minimum and maximum', () => {
    expect(getRenderedBarsBudget(800)).toEqual(400);
    expect(getRenderedBarsBudget(801)).toEqual(400);
    expect(getRenderedBarsBudget(100)).toEqual(MIN_RENDERED_BARS);
    expect(getRenderedBarsBudget(5000)).toEqual(MAX_RENDERED_BARS);
  });

  it('gives the maximum when the width is unknown', () => {
    expect(getRenderedBarsBudget(0)).toEqual(MAX_RENDERED_BARS);
    expect(getRenderedBarsBudget(-10)).toEqual(MAX_RENDERED_BARS);
    expect(getRenderedBarsBudget(Number.NaN)).toEqual(MAX_RENDERED_BARS);
  });
});

describe('rendered points budget', () => {
  it('shares the bars budget between every series', () => {
    expect(getRenderedPointsBudget('vertical-bar', 800, 20)).toEqual(getRenderedBarsBudget(800));
  });

  it('gives each line or area series a point every 2 pixels', () => {
    expect(getRenderedPointsBudget('line', 700, 1)).toEqual(350);
    expect(getRenderedPointsBudget('area', 700, 50)).toEqual(350 * 50);
  });

  it('gives each heatmap series a cell every 6 pixels', () => {
    expect(getRenderedPointsBudget('heatmap', 600, 10)).toEqual(100 * 10);
  });

  it('keeps a few points per series on a tiny or unknown width', () => {
    expect(getRenderedPointsBudget('heatmap', 12, 2)).toEqual(10 * 2);
    expect(getRenderedPointsBudget('line', 0, 1)).toEqual((MAX_RENDERED_BARS * 2) / 2);
  });
});

describe('nextBreakdownChartWidth', () => {
  it('takes the first measured width', () => {
    expect(nextBreakdownChartWidth(undefined, 800)).toEqual(800);
  });

  it('keeps the previous width on a small resize, and changes it from 20 %', () => {
    expect(nextBreakdownChartWidth(800, 900)).toEqual(800); // +12.5 %
    expect(nextBreakdownChartWidth(800, 700)).toEqual(800); // -12.5 %
    expect(nextBreakdownChartWidth(800, 960)).toEqual(960); // +20 %
    expect(nextBreakdownChartWidth(800, 500)).toEqual(500);
  });
});

describe('getBreakdownTickAmount', () => {
  it('gives a label per 60 pixels, at least 2', () => {
    expect(getBreakdownTickAmount(1200)).toEqual(20);
    expect(getBreakdownTickAmount(130)).toEqual(2);
    expect(getBreakdownTickAmount(0)).toEqual(2);
  });
});

describe('coarsenSeriesForRendering', () => {
  it('keeps the series untouched under the budget', () => {
    const series = [{ name: 'A', data: daily('2026-01-01T00:00:00.000Z', [1, 2, 3]) }];
    const result = coarsenSeriesForRendering(series, 'day', 10);
    expect(result.interval).toEqual('day');
    expect(result.series).toBe(series);
    expect(result.pointsCount).toEqual(3);
  });

  it('sums days into weeks starting on Monday', () => {
    // 2026-01-01 is a Thursday: Thu-Sun belong to the week of Monday 2025-12-29
    const series = [{ name: 'A', data: daily('2026-01-01T00:00:00.000Z', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) }];
    const result = coarsenSeriesForRendering(series, 'day', 5);
    expect(result.interval).toEqual('week');
    expect(result.series[0].data).toEqual([
      { x: new Date('2025-12-29T00:00:00.000Z'), y: 1 + 2 + 3 + 4 },
      { x: new Date('2026-01-05T00:00:00.000Z'), y: 5 + 6 + 7 + 8 + 9 + 10 },
    ]);
    expect(result.series[0].name).toEqual('A');
  });

  it('keeps getting coarser until the budget is met, without losing any count', () => {
    const values = Array.from({ length: 366 }, (_, i) => i % 7);
    const series = Array.from({ length: 20 }, (_, i) => ({ name: `S${i}`, data: daily('2025-10-01T00:00:00.000Z', values) }));
    const total = values.reduce((sum, value) => sum + value, 0);

    const toWeeks = coarsenSeriesForRendering(series, 'day', 1200);
    expect(toWeeks.interval).toEqual('week');
    expect(toWeeks.pointsCount).toBeLessThanOrEqual(1200);

    const toMonths = coarsenSeriesForRendering(series, 'day', 600);
    expect(toMonths.interval).toEqual('month');
    expect(toMonths.series[0].data).toHaveLength(13); // October 2025 to October 2026 included
    toMonths.series.forEach((serie) => {
      expect(serie.data.reduce((sum, point) => sum + point.y, 0)).toEqual(total);
    });
  });

  it('coarsens a week series with a smaller budget', () => {
    const values = Array.from({ length: 366 }, (_, i) => i % 7);
    const series = [{ name: 'A', data: daily('2025-10-01T00:00:00.000Z', values) }];
    expect(coarsenSeriesForRendering(series, 'day', MIN_RENDERED_BARS).interval).toEqual('week');
    const result = coarsenSeriesForRendering(series, 'week', 20);
    expect(result.interval).toEqual('month');
    expect(result.pointsCount).toEqual(13);
  });

  it('never goes beyond years', () => {
    const series = [{ name: 'A', data: daily('2026-01-01T00:00:00.000Z', [1, 2]) }];
    const result = coarsenSeriesForRendering(series, 'year', 1);
    expect(result.interval).toEqual('year');
    expect(result.series).toBe(series);
  });
});
