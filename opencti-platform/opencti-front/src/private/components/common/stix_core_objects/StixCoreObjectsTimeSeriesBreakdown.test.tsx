import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import type { Widget, WidgetDataSelection } from '../../../../utils/widget/widget';
import type { FilterDefinition } from '../../../../utils/hooks/useAuth';
import { daysAgo, monthsAgo } from '../../../../utils/Time';

const mocks = vi.hoisted(() => ({
  response: {} as Record<string, unknown>,
  dashboardViz: vi.fn(),
  bars: vi.fn(),
  lines: vi.fn(),
  areas: vi.fn(),
  heatmap: vi.fn(),
}));

vi.mock('react-relay', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-relay')>()),
  usePreloadedQuery: () => mocks.response,
}));
vi.mock('../../../../components/dashboard/useDashboardViz', () => ({
  default: (args: unknown) => {
    mocks.dashboardViz(args);
    return { renderGuards: { isMissingHostEntity: false, isMissingSavedFilters: false, hasUnresolvedVariables: false }, isPreviewMode: false, queryRef: {} };
  },
}));
vi.mock('../../../../components/dashboard/WidgetRenderContent', () => ({
  default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));
vi.mock('../../../../components/dashboard/WidgetContainer', () => ({
  default: ({ children, warning }: { children: React.ReactNode; warning?: string }) => (
    <div>
      {warning && <div data-testid="widget-warning">{warning}</div>}
      {children}
    </div>
  ),
}));
vi.mock('../../../../components/dashboard/WidgetVerticalBars', () => ({
  default: (props: unknown) => {
    mocks.bars(props);
    return <div data-testid="bars" />;
  },
}));
vi.mock('../../../../components/dashboard/WidgetMultiLines', () => ({
  default: (props: unknown) => {
    mocks.lines(props);
    return <div data-testid="lines" />;
  },
}));
vi.mock('../../../../components/dashboard/WidgetMultiAreas', () => ({
  default: (props: unknown) => {
    mocks.areas(props);
    return <div data-testid="areas" />;
  },
}));
vi.mock('../../../../components/dashboard/WidgetMultiHeatMap', () => ({
  default: (props: unknown) => {
    mocks.heatmap(props);
    return <div data-testid="heatmap" />;
  },
}));

import StixCoreObjectsTimeSeriesBreakdown from './StixCoreObjectsTimeSeriesBreakdown';

const config = { relativeDate: null, startDate: '2025-10-01T00:00:00.000Z', endDate: '2026-10-01T00:00:00.000Z' };
const host = { kind: 'workspace' } as const;
const selection = {
  date_attribute: 'published',
  filters: {
    mode: 'and',
    filters: [{ key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' }],
    filterGroups: [],
  },
} as unknown as WidgetDataSelection;

// Several types: the entity type is then a field the dataset can be broken down by
const multiTypesSelection = {
  ...selection,
  filters: {
    mode: 'and',
    filters: [{ key: 'entity_type', values: ['Report', 'Malware'], operator: 'eq', mode: 'or' }],
    filterGroups: [],
  },
} as unknown as WidgetDataSelection;
// Without type filter, the dataset is the abstract Stix-Core-Object type
const noTypeSelection = { ...selection, filters: { mode: 'and', filters: [], filterGroups: [] } } as unknown as WidgetDataSelection;

const makeWidget = (type: string, parameters: Widget['parameters'], dataSelection = selection): Widget => ({
  id: 'widget',
  type,
  perspective: 'entities',
  dataSelection: [dataSelection],
  parameters,
});

const definition = (filterKey: string, subEntityTypes: string[]): FilterDefinition => ({
  filterKey, type: 'id', label: filterKey, multiple: true, subEntityTypes, elementsForFilterValuesSearch: [],
});
const filterKeysSchema = new Map<string, Map<string, FilterDefinition>>([
  ['Report', new Map([
    ['objectAssignee', definition('objectAssignee', ['Report'])],
    ['objectLabel', definition('objectLabel', ['Report'])],
    ['creator_id', definition('creator_id', ['Report'])],
  ])],
  // the abstract type has no assignee
  ['Stix-Core-Object', new Map([['objectLabel', definition('objectLabel', ['Stix-Core-Object', 'Report'])]])],
]);
const userContext = createMockUserContext({ schema: { filterKeysSchema } });

const dailyData = (days: number) => Array.from({ length: days }, (_, i) => ({
  date: new Date(Date.UTC(2025, 9, 1 + i)).toISOString(),
  value: i % 3,
}));

const respond = (series: unknown[], truncated = false) => {
  mocks.response = { stixCoreObjectsTimeSeriesBreakdown: { truncated, series } };
};

const render = (widget: Widget) => testRender(
  <StixCoreObjectsTimeSeriesBreakdown widget={widget} config={config} host={host} />,
  { userContext },
);

describe('StixCoreObjectsTimeSeriesBreakdown', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('queries one breakdown with the dataset filters, date attribute and series limit', () => {
    respond([]);
    render(makeWidget('line', { breakdownBy: 'objectAssignee', breakdownLimit: 20, interval: 'week' }));

    const { buildQueryVariables, dataSelection, parameters } = mocks.dashboardViz.mock.calls[0][0];
    const variables = buildQueryVariables(dataSelection, config, parameters);
    expect(variables).toMatchObject({
      field: 'objectAssignee',
      dateAttribute: 'published',
      startDate: config.startDate,
      endDate: config.endDate,
      interval: 'week',
      limit: 20,
      order: 'desc',
      includeOther: false,
      // the dataset filters on reports: the API validates the field against this type
      types: ['Report'],
    });
    expect(JSON.stringify(variables.filters)).toContain('Report');
  });

  it('sends the order and the other serie options of the widget', () => {
    respond([]);
    render(makeWidget('line', { breakdownBy: 'objectLabel', breakdownOrder: 'asc', breakdownOther: true }));

    const { buildQueryVariables, dataSelection, parameters } = mocks.dashboardViz.mock.calls[0][0];
    expect(buildQueryVariables(dataSelection, config, parameters)).toMatchObject({ order: 'asc', includeOther: true });
  });

  it('keeps the dashboard dates, and defaults a daily breakdown to the last 30 days', () => {
    respond([]);
    render(makeWidget('line', { breakdownBy: 'objectLabel', interval: 'day' }));
    const { buildQueryVariables, dataSelection, parameters } = mocks.dashboardViz.mock.calls[0][0];

    const explicit = buildQueryVariables(dataSelection, config, parameters);
    expect(explicit.startDate).toEqual(config.startDate);
    expect(explicit.endDate).toEqual(config.endDate);

    const withoutDates = buildQueryVariables(dataSelection, {}, parameters);
    expect(withoutDates.startDate).toEqual(daysAgo(30));
    expect(withoutDates.endDate).toBeTruthy();
    // the default start date also restricts the entities the top values are computed on
    expect(JSON.stringify(withoutDates.filters)).toContain(daysAgo(30));

    const weekly = buildQueryVariables(dataSelection, {}, { ...parameters, interval: 'week' });
    expect(weekly.startDate).toEqual(monthsAgo(12));
  });

  it('names the series after the entity, or the translated entity type', () => {
    respond([
      { label: 'user-id', entity: { id: 'user-id', name: 'Alice' }, data: dailyData(3) },
      { label: 'unresolved-id', entity: null, data: dailyData(3) },
    ]);
    render(makeWidget('line', { breakdownBy: 'creator_id' }));
    expect(mocks.lines.mock.calls[0][0].series.map((serie: { name: string }) => serie.name)).toEqual(['Alice', 'unresolved-id']);

    vi.clearAllMocks();
    respond([
      { label: 'Report', entity: null, data: dailyData(3) },
      { label: 'Not-A-Translated-Type', entity: null, data: dailyData(3) },
    ]);
    render(makeWidget('area', { breakdownBy: 'entity_type' }, multiTypesSelection));
    const names = mocks.areas.mock.calls[0][0].series.map((serie: { name: string }) => serie.name);
    expect(names[0]).not.toEqual('entity_Report');
    expect(names[1]).toEqual('Not-A-Translated-Type');
  });

  it('names the other serie and makes it grey, keeping the order of the API', () => {
    respond([
      { label: 'user-id', isOther: false, entity: { id: 'user-id', name: 'Alice' }, data: dailyData(3) },
      { label: 'Other', isOther: true, entity: null, data: dailyData(3) },
    ]);
    render(makeWidget('line', { breakdownBy: 'creator_id' }));
    const names = mocks.lines.mock.calls[0][0].series.map((serie: { name: string }) => serie.name);
    expect(names).toEqual(['Alice', 'Other']);
    const [alice, other] = mocks.lines.mock.calls[0][0].series;
    expect(alice.color).toBeUndefined();
    expect(other.color).toBeTruthy();
  });

  it('keeps the requested interval for lines and heatmaps', () => {
    const series = Array.from({ length: 20 }, (_, i) => ({ label: `Type-${i}`, entity: null, data: dailyData(366) }));
    respond(series);
    render(makeWidget('line', { breakdownBy: 'entity_type' }, multiTypesSelection));
    expect(mocks.lines.mock.calls[0][0].interval).toEqual('day');
    expect(mocks.lines.mock.calls[0][0].series[0].data).toHaveLength(366);

    render(makeWidget('heatmap', { breakdownBy: 'entity_type' }, multiTypesSelection));
    expect(mocks.heatmap.mock.calls[0][0].data[0].data).toHaveLength(366);
    expect(mocks.heatmap.mock.calls[0][0]).toMatchObject({ minValue: 0, maxValue: 2 });
  });

  it('coarsens a large bar chart, disables its animations and says so', () => {
    const series = Array.from({ length: 20 }, (_, i) => ({ label: `Type-${i}`, entity: null, data: dailyData(366) }));
    respond(series);
    const { getByTestId } = render(makeWidget('vertical-bar', { breakdownBy: 'entity_type' }, multiTypesSelection));

    const props = mocks.bars.mock.lastCall?.[0];
    expect(props.interval).toEqual('week');
    expect(props.series).toHaveLength(20);
    expect(props.series[0].data.length).toBeLessThan(60);
    expect(props.isAnimated).toBe(false);
    expect(getByTestId('widget-warning').textContent).toContain('Interval adjusted to');
  });

  it('keeps a small bar chart as configured', () => {
    respond([{ label: 'Report', entity: null, data: dailyData(30) }]);
    const { queryByTestId } = render(makeWidget('vertical-bar', { breakdownBy: 'entity_type', stacked: true }, multiTypesSelection));

    const props = mocks.bars.mock.lastCall?.[0];
    expect(props).toMatchObject({ interval: 'day', isStacked: true, isAnimated: true });
    expect(queryByTestId('widget-warning')).toBeNull();
  });

  it('warns when only the top values are displayed', () => {
    respond([{ label: 'Report', entity: null, data: dailyData(3) }], true);
    const { getByTestId } = render(makeWidget('line', { breakdownBy: 'entity_type', breakdownLimit: 5 }, multiTypesSelection));
    expect(getByTestId('widget-warning').textContent).toContain('5');
  });

  it('warns that only the lowest values are displayed when ordered by lowest values', () => {
    respond([{ label: 'Report', entity: null, data: dailyData(3) }], true);
    const { getByTestId } = render(makeWidget('line', { breakdownBy: 'entity_type', breakdownLimit: 5, breakdownOrder: 'asc' }, multiTypesSelection));
    expect(getByTestId('widget-warning').textContent).toContain('Only the 5 lowest values are displayed.');
  });

  it('does not query a breakdown field the dataset does not support, and says so', () => {
    const { getByText } = render(makeWidget('line', { breakdownBy: 'objectAssignee' }, noTypeSelection));
    expect(mocks.dashboardViz).not.toHaveBeenCalled();
    expect(getByText('This breakdown field is not available for the dataset of this widget. Edit the widget to choose another field.')).toBeTruthy();
  });

  it('shows the no data state without any series', () => {
    respond([]);
    const { queryByTestId } = render(makeWidget('line', { breakdownBy: 'entity_type' }, multiTypesSelection));
    expect(queryByTestId('lines')).toBeNull();
  });
});
