import { describe, expect, it } from 'vitest';
import type { Widget } from './widget';
import type { FilterDefinition } from '../hooks/useAuth';
import type { FilterGroup } from '../filters/filtersHelpers-types';
import {
  coarsenSeriesForRendering,
  getBreakdownEntityTypes,
  getBreakdownFieldOptions,
  getWidgetBreakdownLimit,
  hasWidgetBreakdown,
  isWidgetBreakdownActive,
  isWidgetBreakdownEligible,
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

  it('rejects other visualizations, perspectives, several datasets and drafts', () => {
    expect(isWidgetBreakdownEligible(makeWidget({ type: 'donut' }), workspace)).toBe(false);
    expect(isWidgetBreakdownEligible(makeWidget({ perspective: 'relationships' }), workspace)).toBe(false);
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
});

describe('getBreakdownFieldOptions', () => {
  const definition = (filterKey: string, type: string, label: string, subEntityTypes: string[]): FilterDefinition => ({
    filterKey, type, label, multiple: true, subEntityTypes, elementsForFilterValuesSearch: [],
  });
  const schema = new Map<string, Map<string, FilterDefinition>>([
    ['Report', new Map([
      ['createdBy', definition('createdBy', 'id', 'Author', ['Report'])],
      ['objectLabel', definition('objectLabel', 'id', 'Label', ['Report'])],
      ['report_types', definition('report_types', 'vocabulary', 'Report types', ['Report'])],
      ['name', definition('name', 'string', 'Name', ['Report'])],
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
      ['createdBy', definition('createdBy', 'id', 'Author', ['Stix-Core-Object', 'Report', 'Malware'])],
      // only some sub types carry report types
      ['report_types', definition('report_types', 'vocabulary', 'Report types', ['Report'])],
    ])],
  ]);
  const keys = (entityTypes: string[]) => getBreakdownFieldOptions(schema, entityTypes).map(({ key }) => key);

  it('offers every field of a single type that can be broken down', () => {
    expect(keys(['Report'])).toEqual(['createdBy', 'objectLabel', 'report_types']);
  });

  it('offers the fields shared by several types, and the entity type', () => {
    expect(keys(['Report', 'Malware'])).toEqual(['createdBy', 'entity_type', 'objectLabel']);
  });

  it('offers the fields of the abstract type without type filter', () => {
    expect(keys([])).toEqual(['createdBy', 'entity_type']);
  });
});

describe('coarsenSeriesForRendering', () => {
  it('keeps the series untouched under the budget', () => {
    const series = [{ name: 'A', data: daily('2026-01-01T00:00:00.000Z', [1, 2, 3]) }];
    const result = coarsenSeriesForRendering(series, 'day', 10);
    expect(result.interval).toEqual('day');
    expect(result.series).toBe(series);
    expect(result.barsCount).toEqual(3);
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
    expect(toWeeks.barsCount).toBeLessThanOrEqual(1200);

    const toMonths = coarsenSeriesForRendering(series, 'day', 600);
    expect(toMonths.interval).toEqual('month');
    expect(toMonths.series[0].data).toHaveLength(13); // October 2025 to October 2026 included
    toMonths.series.forEach((serie) => {
      expect(serie.data.reduce((sum, point) => sum + point.y, 0)).toEqual(total);
    });
  });

  it('never goes beyond years', () => {
    const series = [{ name: 'A', data: daily('2026-01-01T00:00:00.000Z', [1, 2]) }];
    const result = coarsenSeriesForRendering(series, 'year', 1);
    expect(result.interval).toEqual('year');
    expect(result.series).toBe(series);
  });
});
