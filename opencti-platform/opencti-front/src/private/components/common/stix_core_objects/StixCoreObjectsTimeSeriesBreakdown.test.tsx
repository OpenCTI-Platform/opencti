import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import type { Widget, WidgetDataSelection } from '../../../../utils/widget/widget';

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
    return { isMissingHostEntity: false, isMissingSavedFilters: false, isPreviewMode: false, queryRef: {} };
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

const makeWidget = (type: string, parameters: Widget['parameters']): Widget => ({
  id: 'widget',
  type,
  perspective: 'entities',
  dataSelection: [selection],
  parameters,
});

const dailyData = (days: number) => Array.from({ length: days }, (_, i) => ({
  date: new Date(Date.UTC(2025, 9, 1 + i)).toISOString(),
  value: i % 3,
}));

const respond = (series: unknown[], truncated = false) => {
  mocks.response = { stixCoreObjectsTimeSeriesBreakdown: { truncated, series } };
};

const render = (widget: Widget) => testRender(
  <StixCoreObjectsTimeSeriesBreakdown widget={widget} config={config} host={host} />,
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
      // the dataset filters on reports: the API validates the field against this type
      types: ['Report'],
    });
    expect(JSON.stringify(variables.filters)).toContain('Report');
  });

  it('names the series after the entity, or the translated entity type', () => {
    respond([
      { label: 'user-id', entity: { id: 'user-id', name: 'Alice' }, data: dailyData(3) },
      { label: 'unresolved-id', entity: null, data: dailyData(3) },
    ]);
    render(makeWidget('line', { breakdownBy: 'creator' }));
    expect(mocks.lines.mock.calls[0][0].series.map((serie: { name: string }) => serie.name)).toEqual(['Alice', 'unresolved-id']);

    vi.clearAllMocks();
    respond([
      { label: 'Report', entity: null, data: dailyData(3) },
      { label: 'Not-A-Translated-Type', entity: null, data: dailyData(3) },
    ]);
    render(makeWidget('area', { breakdownBy: 'entity_type' }));
    const names = mocks.areas.mock.calls[0][0].series.map((serie: { name: string }) => serie.name);
    expect(names[0]).not.toEqual('entity_Report');
    expect(names[1]).toEqual('Not-A-Translated-Type');
  });

  it('keeps the requested interval for lines and heatmaps', () => {
    const series = Array.from({ length: 20 }, (_, i) => ({ label: `Type-${i}`, entity: null, data: dailyData(366) }));
    respond(series);
    render(makeWidget('line', { breakdownBy: 'entity_type' }));
    expect(mocks.lines.mock.calls[0][0].interval).toEqual('day');
    expect(mocks.lines.mock.calls[0][0].series[0].data).toHaveLength(366);

    render(makeWidget('heatmap', { breakdownBy: 'entity_type' }));
    expect(mocks.heatmap.mock.calls[0][0].data[0].data).toHaveLength(366);
    expect(mocks.heatmap.mock.calls[0][0]).toMatchObject({ minValue: 0, maxValue: 2 });
  });

  it('coarsens a large bar chart, disables its animations and says so', () => {
    const series = Array.from({ length: 20 }, (_, i) => ({ label: `Type-${i}`, entity: null, data: dailyData(366) }));
    respond(series);
    const { getByTestId } = render(makeWidget('vertical-bar', { breakdownBy: 'entity_type' }));

    const props = mocks.bars.mock.lastCall?.[0];
    expect(props.interval).toEqual('week');
    expect(props.series).toHaveLength(20);
    expect(props.series[0].data.length).toBeLessThan(60);
    expect(props.isAnimated).toBe(false);
    expect(getByTestId('widget-warning').textContent).toContain('Interval adjusted to');
  });

  it('keeps a small bar chart as configured', () => {
    respond([{ label: 'Report', entity: null, data: dailyData(30) }]);
    const { queryByTestId } = render(makeWidget('vertical-bar', { breakdownBy: 'entity_type', stacked: true }));

    const props = mocks.bars.mock.lastCall?.[0];
    expect(props).toMatchObject({ interval: 'day', isStacked: true, isAnimated: true });
    expect(queryByTestId('widget-warning')).toBeNull();
  });

  it('warns when only the top values are displayed', () => {
    respond([{ label: 'Report', entity: null, data: dailyData(3) }], true);
    const { getByTestId } = render(makeWidget('line', { breakdownBy: 'entity_type', breakdownLimit: 5 }));
    expect(getByTestId('widget-warning').textContent).toContain('5');
  });

  it('shows the no data state without any series', () => {
    respond([]);
    const { queryByTestId } = render(makeWidget('line', { breakdownBy: 'entity_type' }));
    expect(queryByTestId('lines')).toBeNull();
  });
});
