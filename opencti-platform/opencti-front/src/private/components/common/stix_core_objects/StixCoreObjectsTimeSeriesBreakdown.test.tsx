import React, { useState } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Mock } from 'vitest';
import { act, waitFor } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import type { Widget, WidgetDataSelection } from '../../../../utils/widget/widget';
import type { FilterDefinition } from '../../../../utils/hooks/useAuth';
import { daysAgo, monthsAgo } from '../../../../utils/Time';

const mocks = vi.hoisted(() => ({
  response: {} as Record<string, unknown>,
  error: null as unknown,
  dashboardViz: vi.fn(),
  resolvedDataSelection: null as unknown[] | null,
  bars: vi.fn(),
  lines: vi.fn(),
  areas: vi.fn(),
  heatmap: vi.fn(),
  width: 1200,
}));

vi.mock('../../../../utils/hooks/useResizeObserver', () => ({ default: () => ({ width: mocks.width, height: 400 }) }));
vi.mock('react-relay', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-relay')>()),
  usePreloadedQuery: () => {
    if (mocks.error) throw mocks.error;
    return mocks.response;
  },
}));
vi.mock('../../../../components/dashboard/useDashboardViz', () => ({
  default: (args: unknown) => {
    mocks.dashboardViz(args);
    // Resolved as is, unless the test sets what its saved filters and variables resolve to
    const resolvedDataSelection = mocks.resolvedDataSelection ?? (args as { dataSelection: unknown[] }).dataSelection;
    return { renderGuards: { isMissingHostEntity: false, isMissingSavedFilters: false, hasUnresolvedVariables: false }, isPreviewMode: false, queryRef: {}, resolvedDataSelection };
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

const dailyValues = (days: number) => Array.from({ length: days }, (_, i) => i % 3);

type SerieFixture = { label: string; isOther?: boolean; entity: Record<string, string> | null; values: number[] };
// The dates are shared by every series, which carry one value per date
const respond = (series: SerieFixture[], truncated = false) => {
  const days = Math.max(0, ...series.map((serie) => serie.values.length));
  const dates = Array.from({ length: days }, (_, i) => new Date(Date.UTC(2025, 9, 1 + i)).toISOString());
  mocks.response = { stixCoreObjectsTimeSeriesBreakdown: { truncated, dates, series } };
};

const render = (widget: Widget) => testRender(
  <StixCoreObjectsTimeSeriesBreakdown widget={widget} config={config} host={host} />,
  { userContext },
);

// The first draw of a chart can wait for the charts drawn just before it
const drawn = async (chart: Mock) => {
  await waitFor(() => expect(chart).toHaveBeenCalled());
  return chart.mock.lastCall?.[0];
};

describe('StixCoreObjectsTimeSeriesBreakdown', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.width = 1200;
    mocks.error = null;
    mocks.resolvedDataSelection = null;
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

  it('looks back from the end date of a dashboard that sets only this one', () => {
    respond([]);
    render(makeWidget('line', { breakdownBy: 'objectLabel', interval: 'day' }));
    const { buildQueryVariables, dataSelection, parameters } = mocks.dashboardViz.mock.calls[0][0];

    // Long ago: 30 days back from today would start after the end
    const endDate = '2024-01-15T12:00:00.000Z';
    const variables = buildQueryVariables(dataSelection, { relativeDate: null, startDate: null, endDate }, parameters);
    expect(variables.endDate).toEqual(endDate);
    expect(variables.startDate).toEqual(daysAgo(30, endDate));
    const lookBackDays = (new Date(endDate).getTime() - new Date(variables.startDate).getTime()) / 86400000;
    expect(lookBackDays).toBeGreaterThanOrEqual(30);
    expect(lookBackDays).toBeLessThan(31);
    // the entities the top values are computed on are restricted to the same period
    expect(JSON.stringify(variables.filters)).toContain(daysAgo(30, endDate));
  });

  it('names the series after the entity, or the translated entity type', async () => {
    respond([
      { label: 'user-id', entity: { id: 'user-id', name: 'Alice' }, values: dailyValues(3) },
      { label: 'unresolved-id', entity: null, values: dailyValues(3) },
    ]);
    render(makeWidget('line', { breakdownBy: 'creator_id' }));
    expect((await drawn(mocks.lines)).series.map((serie: { name: string }) => serie.name)).toEqual(['Alice', 'unresolved-id']);

    vi.clearAllMocks();
    respond([
      { label: 'Report', entity: null, values: dailyValues(3) },
      { label: 'Not-A-Translated-Type', entity: null, values: dailyValues(3) },
    ]);
    render(makeWidget('area', { breakdownBy: 'entity_type' }, multiTypesSelection));
    const names = (await drawn(mocks.areas)).series.map((serie: { name: string }) => serie.name);
    expect(names[0]).not.toEqual('entity_Report');
    expect(names[1]).toEqual('Not-A-Translated-Type');
  });

  it('numbers the restricted entities, all named the same, to tell them apart in the legend', async () => {
    // The API sends an entity the user cannot access with its id, its type and the name "Restricted"
    const restricted = (id: string) => ({ id, entity_type: 'User', name: 'Restricted' });
    respond([
      { label: 'user-a', entity: restricted('user-a'), values: dailyValues(3) },
      { label: 'user-b', entity: { id: 'user-b', entity_type: 'User', name: 'Alice' }, values: dailyValues(3) },
      { label: 'user-c', entity: restricted('user-c'), values: dailyValues(3) },
      { label: 'Other', isOther: true, entity: null, values: dailyValues(3) },
    ]);
    render(makeWidget('line', { breakdownBy: 'creator_id' }));
    expect((await drawn(mocks.lines)).series.map((serie: { name: string }) => serie.name))
      .toEqual(['Restricted (1)', 'Alice', 'Restricted (2)', 'Other']);
  });

  it('names the other serie and makes it grey, keeping the order of the API', async () => {
    respond([
      { label: 'user-id', isOther: false, entity: { id: 'user-id', name: 'Alice' }, values: dailyValues(3) },
      { label: 'Other', isOther: true, entity: null, values: dailyValues(3) },
    ]);
    render(makeWidget('line', { breakdownBy: 'creator_id' }));
    const { series } = await drawn(mocks.lines);
    expect(series.map((serie: { name: string }) => serie.name)).toEqual(['Alice', 'Other']);
    const [alice, other] = series;
    expect(alice.color).toBeUndefined();
    expect(other.color).toBeTruthy();
  });

  it('places the values of every series on the shared dates', async () => {
    respond([{ label: 'Report', entity: null, values: [4, 0, 7] }]);
    render(makeWidget('line', { breakdownBy: 'entity_type' }, multiTypesSelection));
    expect((await drawn(mocks.lines)).series[0].data).toEqual([
      { x: new Date('2025-10-01T00:00:00.000Z'), y: 4 },
      { x: new Date('2025-10-02T00:00:00.000Z'), y: 0 },
      { x: new Date('2025-10-03T00:00:00.000Z'), y: 7 },
    ]);
  });

  it('keeps the requested interval for lines the chart width can show, without animating many points', async () => {
    const series = Array.from({ length: 10 }, (_, i) => ({ label: `Type-${i}`, entity: null, values: dailyValues(366) }));
    respond(series);
    render(makeWidget('line', { breakdownBy: 'entity_type' }, multiTypesSelection));
    // 1200 px show 600 points per line, and 10 lines stay under the points cap of the chart
    const lines = await drawn(mocks.lines);
    expect(lines).toMatchObject({ interval: 'day', isAnimated: false, isUpdateAnimated: false });
    expect(lines.series[0].data).toHaveLength(366);
  });

  it('coarsens lines, areas and heatmaps the chart width cannot show, and says so', async () => {
    const series = Array.from({ length: 20 }, (_, i) => ({ label: `Type-${i}`, entity: null, values: dailyValues(366) }));
    respond(series);
    // 1200 px show 200 heatmap cells per series, but 20 series share at most 1500 cells: 75 per series
    const { findByTestId } = render(makeWidget('heatmap', { breakdownBy: 'entity_type' }, multiTypesSelection));
    const heatmap = await drawn(mocks.heatmap);
    expect(heatmap).toMatchObject({ interval: 'week', isAnimated: false, isUpdateAnimated: false });
    expect(heatmap.data[0].data.length).toBeLessThanOrEqual(75);
    expect(heatmap.minValue).toBeLessThan(heatmap.maxValue);
    expect((await findByTestId('widget-warning')).textContent).toContain('Interval adjusted to');

    // 300 px show 150 points per line or area
    mocks.width = 300;
    render(makeWidget('line', { breakdownBy: 'entity_type' }, multiTypesSelection));
    expect((await drawn(mocks.lines)).interval).toEqual('week');
    render(makeWidget('area', { breakdownBy: 'entity_type' }, multiTypesSelection));
    expect(await drawn(mocks.areas)).toMatchObject({ interval: 'week', isAnimated: false });
  });

  it('coarsens a large bar chart, disables its animations and says so', async () => {
    const series = Array.from({ length: 40 }, (_, i) => ({ label: `Type-${i}`, entity: null, values: dailyValues(366) }));
    respond(series);
    const { findByTestId } = render(makeWidget('vertical-bar', { breakdownBy: 'entity_type' }, multiTypesSelection));

    const props = await drawn(mocks.bars);
    // 1200 px allow 600 bars: 40 weekly series are still too many
    expect(props.interval).toEqual('month');
    expect(props.series).toHaveLength(40);
    expect(props.series[0].data.length).toBeLessThan(20);
    expect(props.isAnimated).toBe(false);
    expect(props.hasHoverFilter).toBe(false);
    expect(props.tickAmount).toEqual(20);
    const warning = (await findByTestId('widget-warning')).textContent;
    expect(warning).toContain('Interval adjusted to');
    // Days summed into months stay exact
    expect(warning).not.toContain('Each week');
  });

  it('says that weeks summed into months are counted in the month of their Monday', async () => {
    // 53 Mondays from 2025-09-29
    const dates = Array.from({ length: 53 }, (_, i) => new Date(Date.UTC(2025, 8, 29 + 7 * i)).toISOString());
    const series = Array.from({ length: 20 }, (_, i) => ({ label: `Type-${i}`, isOther: false, entity: null, values: dailyValues(53) }));
    mocks.response = { stixCoreObjectsTimeSeriesBreakdown: { truncated: false, dates, series } };
    const { findByTestId } = render(makeWidget('vertical-bar', { breakdownBy: 'entity_type', interval: 'week' }, multiTypesSelection));

    // 1200 px allow 600 bars: 20 series of 53 weeks are too many
    expect((await drawn(mocks.bars)).interval).toEqual('month');
    const warning = (await findByTestId('widget-warning')).textContent;
    expect(warning).toContain('Interval adjusted to');
    expect(warning).toContain('Each week is counted in full in the interval that contains its Monday.');
  });

  it('coarsens less on a wide chart, and more on a narrow one', async () => {
    const series = Array.from({ length: 3 }, (_, i) => ({ label: `Type-${i}`, entity: null, values: dailyValues(366) }));
    respond(series);
    mocks.width = 2000;
    const { unmount } = render(makeWidget('vertical-bar', { breakdownBy: 'entity_type' }, multiTypesSelection));
    expect((await drawn(mocks.bars)).interval).toEqual('week');
    unmount();

    vi.clearAllMocks();
    mocks.width = 300;
    render(makeWidget('vertical-bar', { breakdownBy: 'entity_type' }, multiTypesSelection));
    expect((await drawn(mocks.bars)).interval).toEqual('month');
  });

  it('does not draw the chart before it is measured', () => {
    respond([{ label: 'Report', entity: null, values: dailyValues(30) }]);
    mocks.width = 0;
    const { queryByTestId } = render(makeWidget('vertical-bar', { breakdownBy: 'entity_type' }, multiTypesSelection));
    expect(queryByTestId('bars')).toBeNull();
    expect(mocks.bars).not.toHaveBeenCalled();
    render(makeWidget('line', { breakdownBy: 'entity_type' }, multiTypesSelection));
    expect(mocks.lines).not.toHaveBeenCalled();
  });

  it('keeps a small bar chart as configured', async () => {
    respond([{ label: 'Report', entity: null, values: dailyValues(30) }]);
    const { queryByTestId } = render(makeWidget('vertical-bar', { breakdownBy: 'entity_type', stacked: true }, multiTypesSelection));

    const props = await drawn(mocks.bars);
    expect(props).toMatchObject({ interval: 'day', isStacked: true, isAnimated: true });
    expect(queryByTestId('widget-warning')).toBeNull();
  });

  it('draws the charts of widgets mounted together one after the other', async () => {
    respond([{ label: 'Report', entity: null, values: dailyValues(30) }]);
    render(makeWidget('line', { breakdownBy: 'entity_type' }, multiTypesSelection));
    render(makeWidget('area', { breakdownBy: 'entity_type' }, multiTypesSelection));
    // the first chart is drawn at once, the second one in a later task
    expect(mocks.lines).toHaveBeenCalled();
    expect(mocks.areas).not.toHaveBeenCalled();
    await drawn(mocks.areas);
  });

  it('does not draw the chart again on a refresh that brings the same values', async () => {
    const widget = makeWidget('line', { breakdownBy: 'entity_type' }, multiTypesSelection);
    let refresh = () => {};
    const RefreshedWidget = () => {
      const [, setRefreshCount] = useState(0);
      refresh = () => setRefreshCount((count) => count + 1);
      return <StixCoreObjectsTimeSeriesBreakdown widget={widget} config={config} host={host} />;
    };
    respond([{ label: 'Report', entity: null, values: [1, 2, 3] }]);
    testRender(<RefreshedWidget />, { userContext });
    const { series } = await drawn(mocks.lines);

    // a refresh hands a new breakdown, with the same values
    respond([{ label: 'Report', entity: null, values: [1, 2, 3] }]);
    act(() => refresh());
    expect(mocks.lines.mock.lastCall?.[0].series).toBe(series);

    respond([{ label: 'Report', entity: null, values: [1, 2, 4] }]);
    act(() => refresh());
    expect(mocks.lines.mock.lastCall?.[0].series).not.toBe(series);
    expect(mocks.lines.mock.lastCall?.[0].series[0].data[2].y).toEqual(4);
  });

  it('says why the API refused the breakdown, and leaves any other error to the widget', () => {
    // React logs the errors its boundaries catch
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const refusal = (message: string, data?: Record<string, unknown>) => ({ res: { errors: [{ message, extensions: { code: 'FUNCTIONAL_ERROR', data } }] } });
    const widget = makeWidget('line', { breakdownBy: 'entity_type' }, multiTypesSelection);
    const tooLarge = 'This breakdown has too many points for the selected period. Shorten the period, choose a coarser interval or reduce the number of series.';
    const tooManyValues = 'There are too many values to find the lowest ones. Choose the highest values or narrow the filters of this widget.';
    const generic = 'This breakdown cannot be computed with the settings of this widget. Edit the widget to change them.';
    const refusedWith = (error: unknown) => {
      mocks.error = error;
      const { container, unmount } = render(widget);
      const { textContent } = container;
      unmount();
      return textContent;
    };

    // The reason of the refusal tells which one it is, whatever its message says
    expect(refusedWith(refusal('Refused', { reason: 'too_large', limit: 50, intervalsCount: 1097, max: 50000 }))).toEqual(tooLarge);
    expect(refusedWith(refusal('Refused', { reason: 'too_many_values', max: 5000 }))).toEqual(tooManyValues);
    // Any other refusal, even one whose message speaks of a size, keeps the generic message
    expect(refusedWith(refusal('Time series breakdown is too large, reduce the period, the interval or the number of series'))).toEqual(generic);
    expect(refusedWith(refusal('Time series breakdown does not support this field for these entity types', { reason: 'unsupported' }))).toEqual(generic);

    mocks.error = new Error('Network error');
    expect(() => render(widget)).toThrow('Network error');
    vi.mocked(console.error).mockRestore();
  });

  it('warns when only the top values are displayed', () => {
    respond([{ label: 'Report', entity: null, values: dailyValues(3) }], true);
    const { getByTestId } = render(makeWidget('line', { breakdownBy: 'entity_type', breakdownLimit: 5 }, multiTypesSelection));
    expect(getByTestId('widget-warning').textContent).toContain('5');
  });

  it('warns that only the lowest values are displayed when ordered by lowest values', () => {
    respond([{ label: 'Report', entity: null, values: dailyValues(3) }], true);
    const { getByTestId } = render(makeWidget('line', { breakdownBy: 'entity_type', breakdownLimit: 5, breakdownOrder: 'asc' }, multiTypesSelection));
    expect(getByTestId('widget-warning').textContent).toContain('Only the 5 lowest values are displayed.');
  });

  it('does not query a breakdown field the dataset does not support, and says so', () => {
    const { getByText } = render(makeWidget('line', { breakdownBy: 'objectAssignee' }, noTypeSelection));
    const { buildQueryVariables, dataSelection, parameters } = mocks.dashboardViz.mock.lastCall?.[0] ?? {};
    expect(buildQueryVariables(dataSelection, config, parameters)).toBeNull();
    expect(getByText('This breakdown field is not available for the dataset of this widget. Edit the widget to choose another field.')).toBeTruthy();
    expect(mocks.lines).not.toHaveBeenCalled();
  });

  it('checks the field on the dataset its saved filters and variables resolve to, as it is queried', async () => {
    // The type is a dashboard variable: only the resolved dataset says it is a report, which has assignees
    const variableSelection = {
      ...selection,
      filters: { mode: 'and', filters: [{ key: 'entity_type', values: ['$var:6f1c3f0e-2b7a-4c1e-9d3a-0a1b2c3d4e5f'], operator: 'eq', mode: 'or' }], filterGroups: [] },
    } as unknown as WidgetDataSelection;
    mocks.resolvedDataSelection = [selection];
    respond([{ label: 'user-1', entity: null, values: dailyValues(3) }]);
    render(makeWidget('line', { breakdownBy: 'objectAssignee' }, variableSelection));
    const { buildQueryVariables, parameters } = mocks.dashboardViz.mock.lastCall?.[0] ?? {};
    expect(buildQueryVariables([selection], config, parameters)).toMatchObject({ field: 'objectAssignee', types: ['Report'] });
    await drawn(mocks.lines);

    // A dataset whose saved filter resolves to any entity: the same field is refused, without query
    mocks.resolvedDataSelection = [noTypeSelection];
    const { getByText } = render(makeWidget('line', { breakdownBy: 'objectAssignee' }, { ...selection, filters_id: 'saved-filter' } as WidgetDataSelection));
    expect(mocks.dashboardViz.mock.lastCall?.[0].buildQueryVariables([noTypeSelection], config, parameters)).toBeNull();
    expect(getByText('This breakdown field is not available for the dataset of this widget. Edit the widget to choose another field.')).toBeTruthy();
  });

  it('accepts the entity type for a dataset resolved to a single type, a type variable may hold one', () => {
    respond([]);
    render(makeWidget('line', { breakdownBy: 'entity_type' }, selection));
    const { buildQueryVariables, dataSelection, parameters } = mocks.dashboardViz.mock.lastCall?.[0] ?? {};
    expect(buildQueryVariables(dataSelection, config, parameters)).toMatchObject({ field: 'entity_type', types: ['Report'] });
  });

  it('shows the no data state without any series', () => {
    respond([]);
    const { queryByTestId } = render(makeWidget('line', { breakdownBy: 'entity_type' }, multiTypesSelection));
    expect(queryByTestId('lines')).toBeNull();
  });
});
