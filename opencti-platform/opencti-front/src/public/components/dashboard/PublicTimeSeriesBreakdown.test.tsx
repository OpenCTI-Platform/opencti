import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Mock } from 'vitest';
import { act, waitFor } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { Widget } from '../../../utils/widget/widget';
import { daysAgo, monthsAgo } from '../../../utils/Time';

const mocks = vi.hoisted(() => ({
  response: {} as Record<string, unknown>,
  error: null as unknown,
  queryRef: {} as unknown,
  viz: vi.fn(),
  bars: vi.fn(),
  lines: vi.fn(),
}));

vi.mock('../../../utils/hooks/useResizeObserver', () => ({ default: () => ({ width: 1200, height: 400 }) }));
vi.mock('react-relay', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-relay')>()),
  usePreloadedQuery: () => {
    if (mocks.error) throw mocks.error;
    return mocks.response;
  },
}));
// The query of the widget is loaded with these variables
vi.mock('./usePublicDashboardViz', () => ({
  default: (_query: unknown, variables: unknown) => {
    mocks.viz(variables);
    return mocks.queryRef;
  },
}));
vi.mock('../../../components/dashboard/WidgetContainer', () => ({
  default: ({ children, warning, chart }: { children: React.ReactNode; warning?: string; chart?: unknown }) => (
    <div>
      {warning && <div data-testid="widget-warning">{warning}</div>}
      {chart ? <div data-testid="widget-export" /> : null}
      {children}
    </div>
  ),
}));
vi.mock('../../../components/dashboard/WidgetVerticalBars', () => ({
  default: (props: unknown) => {
    mocks.bars(props);
    return <div data-testid="bars" />;
  },
}));
vi.mock('../../../components/dashboard/WidgetMultiLines', () => ({
  default: (props: unknown) => {
    mocks.lines(props);
    return <div data-testid="lines" />;
  },
}));

import PublicStixCoreObjectsTimeSeriesBreakdown from './stix_core_objects/PublicStixCoreObjectsTimeSeriesBreakdown';
import PublicStixRelationshipsTimeSeriesBreakdown from './stix_relationships/PublicStixRelationshipsTimeSeriesBreakdown';

const makeWidget = (type: string, parameters: Widget['parameters'], perspective: 'entities' | 'relationships' = 'entities'): Widget => ({
  id: 'public-widget',
  type,
  perspective,
  // Public manifests strip the filters of the datasets
  dataSelection: [{ label: 'Dataset', perspective }],
  parameters,
} as unknown as Widget);

const breakdown = (values: number[][]) => ({
  truncated: false,
  dates: values[0].map((_, i) => new Date(Date.UTC(2025, 9, 1 + i)).toISOString()),
  series: values.map((serieValues, i) => ({ label: `Type-${i}`, isOther: false, entity: null, values: serieValues })),
});

const variables = () => mocks.viz.mock.lastCall?.[0];
const days = (from: string, to: string) => (new Date(to).getTime() - new Date(from).getTime()) / 86400000;

// The first draw of a chart can wait for the charts drawn just before it
const drawn = async (chart: Mock) => {
  await waitFor(() => expect(chart).toHaveBeenCalled());
  return chart.mock.lastCall?.[0];
};

describe('PublicTimeSeriesBreakdown', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.response = { publicStixCoreObjectsTimeSeriesBreakdown: breakdown([[1, 2, 3]]) };
    mocks.error = null;
    mocks.queryRef = {};
  });

  it('queries the breakdown of the widget, whose settings are read by the API, over the dates of the dashboard', () => {
    const startDate = '2025-10-01T00:00:00.000Z';
    const endDate = '2026-10-01T00:00:00.000Z';
    testRender(<PublicStixCoreObjectsTimeSeriesBreakdown uriKey="public-key" widget={makeWidget('line', { breakdownBy: 'entity_type', interval: 'day' })} startDate={startDate} endDate={endDate} />);

    expect(variables()).toEqual({ uriKey: 'public-key', widgetId: 'public-widget', startDate, endDate });
  });

  it('looks back 30 days for a daily breakdown, 12 months otherwise, without dates on the dashboard', () => {
    testRender(<PublicStixCoreObjectsTimeSeriesBreakdown uriKey="public-key" widget={makeWidget('line', { breakdownBy: 'entity_type', interval: 'day' })} />);
    expect(variables().startDate).toEqual(daysAgo(30));
    expect(variables().endDate).toBeTruthy();

    testRender(<PublicStixCoreObjectsTimeSeriesBreakdown uriKey="public-key" widget={makeWidget('line', { breakdownBy: 'entity_type', interval: 'month' })} />);
    expect(variables().startDate).toEqual(monthsAgo(12));
  });

  it('looks back from the end date of a dashboard that sets only this one', () => {
    // Long ago: 30 days back from today would start after the end
    const endDate = '2024-01-15T12:00:00.000Z';
    testRender(<PublicStixCoreObjectsTimeSeriesBreakdown uriKey="public-key" widget={makeWidget('line', { breakdownBy: 'entity_type', interval: 'day' })} endDate={endDate} />);
    expect(variables()).toMatchObject({ startDate: daysAgo(30, endDate), endDate });
    expect(days(variables().startDate, endDate)).toBeGreaterThanOrEqual(30);
    expect(days(variables().startDate, endDate)).toBeLessThan(31);

    testRender(<PublicStixCoreObjectsTimeSeriesBreakdown uriKey="public-key" widget={makeWidget('line', { breakdownBy: 'entity_type', interval: 'week' })} endDate={endDate} />);
    expect(variables().endDate).toEqual(endDate);
    expect(days(variables().startDate, endDate)).toBeGreaterThanOrEqual(365);
    expect(days(variables().startDate, endDate)).toBeLessThan(366);
  });

  it('draws the breakdown of the entities or of the relationships with the chart of the widget', async () => {
    const { queryByTestId } = testRender(
      <PublicStixCoreObjectsTimeSeriesBreakdown uriKey="public-key" widget={makeWidget('vertical-bar', { breakdownBy: 'entity_type', stacked: true })} />,
    );
    const bars = await drawn(mocks.bars);
    expect(bars).toMatchObject({ interval: 'day', isStacked: true });
    expect(bars.series.map((serie: { data: { y: number }[] }) => serie.data.map(({ y }) => y))).toEqual([[1, 2, 3]]);
    expect(queryByTestId('lines')).toBeNull();

    mocks.response = { publicStixRelationshipsTimeSeriesBreakdown: breakdown([[4, 5], [6, 7]]) };
    testRender(<PublicStixRelationshipsTimeSeriesBreakdown uriKey="public-key" widget={makeWidget('line', { breakdownBy: 'toTypes' }, 'relationships')} />);
    expect((await drawn(mocks.lines)).series).toHaveLength(2);
  });

  it('only says why the API refused the breakdown to its visitors, and stops offering the export of its chart', async () => {
    // React logs the errors its boundaries catch
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const element = <PublicStixCoreObjectsTimeSeriesBreakdown uriKey="public-key" widget={makeWidget('line', { breakdownBy: 'entity_type' })} />;
    const { container, queryByTestId, rerender } = testRender(element);
    const { onMounted } = await drawn(mocks.lines);
    act(() => onMounted({}));
    expect(queryByTestId('widget-export')).not.toBeNull();

    // A refresh refused by the API: the visitors cannot change the period nor the widget
    mocks.error = { res: { errors: [{ message: 'Refused', extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'too_large' } } }] } };
    rerender(element);
    expect(container.textContent).toEqual('This breakdown has too many points for the selected period.');
    expect(queryByTestId('widget-export')).toBeNull();

    // A widget that cannot be broken down any more
    mocks.error = { res: { errors: [{ message: 'This widget cannot be broken down', extensions: { code: 'FUNCTIONAL_ERROR' } }] } };
    mocks.queryRef = {};
    rerender(element);
    expect(container.textContent).toEqual('This breakdown cannot be computed with the settings of this widget.');
    vi.mocked(console.error).mockRestore();
  });

  it('waits for its query', () => {
    mocks.queryRef = null;
    const { queryByTestId } = testRender(<PublicStixCoreObjectsTimeSeriesBreakdown uriKey="public-key" widget={makeWidget('line', { breakdownBy: 'entity_type' })} />);
    expect(queryByTestId('lines')).toBeNull();
    expect(mocks.lines).not.toHaveBeenCalled();
  });
});
