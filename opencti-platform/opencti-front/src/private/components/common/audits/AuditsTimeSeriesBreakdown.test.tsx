import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Mock } from 'vitest';
import { waitFor } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import type { Widget, WidgetDataSelection } from '../../../../utils/widget/widget';
import { daysAgo, monthsAgo } from '../../../../utils/Time';

const mocks = vi.hoisted(() => ({
  response: {} as Record<string, unknown>,
  dashboardViz: vi.fn(),
  lines: vi.fn(),
  bars: vi.fn(),
  isGranted: true,
  isEnterpriseEdition: true,
}));

vi.mock('../../../../utils/hooks/useResizeObserver', () => ({ default: () => ({ width: 1200, height: 400 }) }));
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
vi.mock('../../../../utils/hooks/useGranted', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../utils/hooks/useGranted')>()),
  default: () => mocks.isGranted,
}));
vi.mock('../../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => mocks.isEnterpriseEdition }));
vi.mock('../../../../components/dashboard/WidgetContainer', () => ({
  default: ({ children, warning, title }: { children: React.ReactNode; warning?: string; title?: string }) => (
    <div>
      <div data-testid="widget-title">{title}</div>
      {warning && <div data-testid="widget-warning">{warning}</div>}
      {children}
    </div>
  ),
}));
vi.mock('../../../../components/dashboard/WidgetMultiLines', () => ({
  default: (props: unknown) => {
    mocks.lines(props);
    return <div data-testid="lines" />;
  },
}));
vi.mock('../../../../components/dashboard/WidgetVerticalBars', () => ({
  default: (props: unknown) => {
    mocks.bars(props);
    return <div data-testid="bars" />;
  },
}));

import AuditsTimeSeriesBreakdown from './AuditsTimeSeriesBreakdown';

const config = { relativeDate: null, startDate: '2025-10-01T00:00:00.000Z', endDate: '2026-10-01T00:00:00.000Z' };
const host = { kind: 'workspace' } as const;
const selection = {
  date_attribute: '',
  filters: {
    mode: 'and',
    filters: [
      { key: 'entity_type', values: ['all'], operator: 'eq', mode: 'or' },
      { key: 'event_type', values: ['mutation'], operator: 'eq', mode: 'or' },
    ],
    filterGroups: [],
  },
} as unknown as WidgetDataSelection;

const makeWidget = (type: string, parameters: Widget['parameters'], dataSelection = selection): Widget => ({
  id: 'widget',
  type,
  perspective: 'audits',
  dataSelection: [dataSelection],
  parameters,
});

type SerieFixture = { label: string; isOther?: boolean; entity: Record<string, string> | null; values: number[] };
const respond = (series: SerieFixture[], truncated = false) => {
  const days = Math.max(0, ...series.map((serie) => serie.values.length));
  const dates = Array.from({ length: days }, (_, i) => new Date(Date.UTC(2025, 9, 1 + i)).toISOString());
  mocks.response = { auditsTimeSeriesBreakdown: { truncated, dates, series } };
};

const render = (widget: Widget) => testRender(<AuditsTimeSeriesBreakdown widget={widget} config={config} host={host} />);

// The first draw of a chart can wait for the charts drawn just before it
const drawn = async (chart: Mock) => {
  await waitFor(() => expect(chart).toHaveBeenCalled());
  return chart.mock.lastCall?.[0];
};

const queryVariables = (widget: Widget, dashboardConfig: Record<string, unknown> = config) => {
  const { buildQueryVariables, dataSelection, parameters } = mocks.dashboardViz.mock.lastCall?.[0] ?? {};
  expect(widget.parameters).toEqual(parameters);
  return buildQueryVariables(dataSelection, dashboardConfig, parameters);
};

describe('AuditsTimeSeriesBreakdown', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.isGranted = true;
    mocks.isEnterpriseEdition = true;
  });

  it('queries the logs breakdown with the dataset filters, the timestamp and the series settings', () => {
    respond([]);
    const widget = makeWidget('line', { breakdownBy: 'event_scope', breakdownLimit: 20, breakdownOrder: 'asc', breakdownOther: true, interval: 'week' });
    render(widget);

    expect(mocks.dashboardViz.mock.calls[0][0].perspective).toEqual('audits');
    const variables = queryVariables(widget);
    expect(variables).toMatchObject({
      field: 'event_scope',
      // the other audits time series count on the timestamp of the events
      dateAttribute: 'timestamp',
      startDate: config.startDate,
      endDate: config.endDate,
      interval: 'week',
      limit: 20,
      order: 'asc',
      includeOther: true,
      // the API narrows them to the logs the user can see
      types: ['History', 'Activity'],
    });
    const filters = JSON.stringify(variables.filters);
    expect(filters).toContain('mutation');
    // "all types" is not a filter of the logs
    expect(filters).not.toContain('"all"');
  });

  it('keeps the date attribute of the dataset, and defaults a daily breakdown to the last 30 days', () => {
    respond([]);
    const widget = makeWidget('line', { breakdownBy: 'user_id', interval: 'day' }, { ...selection, date_attribute: 'created_at' });
    render(widget);

    expect(queryVariables(widget).dateAttribute).toEqual('created_at');
    const withoutDates = queryVariables(widget, {});
    expect(withoutDates.startDate).toEqual(daysAgo(30));
    expect(withoutDates.endDate).toBeTruthy();
    const { buildQueryVariables, dataSelection, parameters } = mocks.dashboardViz.mock.lastCall?.[0] ?? {};
    expect(buildQueryVariables(dataSelection, {}, { ...parameters, interval: 'month' }).startDate).toEqual(monthsAgo(12));
  });

  it('names the series after the user, the group, or the translated entity type', async () => {
    respond([
      { label: 'user-id', entity: { id: 'user-id', name: 'Alice' }, values: [1, 2, 3] },
      { label: 'group-id', entity: { id: 'group-id', entity_type: 'Group', name: 'Analysts' }, values: [1, 0, 0] },
    ]);
    render(makeWidget('line', { breakdownBy: 'user_id' }));
    expect((await drawn(mocks.lines)).series.map((serie: { name: string }) => serie.name)).toEqual(['Alice', 'Analysts']);

    vi.clearAllMocks();
    respond([
      { label: 'Report', entity: null, values: [1, 2, 3] },
      { label: 'Not-A-Translated-Type', entity: null, values: [1, 2, 3] },
    ]);
    render(makeWidget('vertical-bar', { breakdownBy: 'context_data.entity_type' }));
    const names = (await drawn(mocks.bars)).series.map((serie: { name: string }) => serie.name);
    expect(names[0]).not.toEqual('entity_Report');
    expect(names[1]).toEqual('Not-A-Translated-Type');
  });

  it('keeps the raw event values and warns when only the top values are displayed', async () => {
    respond([{ label: 'create', entity: null, values: [1, 2, 3] }], true);
    const { getByTestId } = render(makeWidget('line', { breakdownBy: 'event_scope', breakdownLimit: 5 }));
    expect((await drawn(mocks.lines)).series.map((serie: { name: string }) => serie.name)).toEqual(['create']);
    expect(getByTestId('widget-warning').textContent).toContain('5');
  });

  it('is titled like the other audits widgets', () => {
    respond([]);
    const { getByTestId } = render(makeWidget('line', { breakdownBy: 'event_type' }));
    expect(getByTestId('widget-title').textContent).toEqual('Activity and history');
  });

  it('keeps the guards of the audits widgets: capabilities and enterprise edition', () => {
    respond([{ label: 'create', entity: null, values: [1, 2, 3] }]);
    mocks.isGranted = false;
    const denied = render(makeWidget('line', { breakdownBy: 'event_scope' }));
    expect(denied.getByText('You are not authorized to see this data.')).toBeTruthy();
    expect(mocks.lines).not.toHaveBeenCalled();
    denied.unmount();

    mocks.isGranted = true;
    mocks.isEnterpriseEdition = false;
    const community = render(makeWidget('line', { breakdownBy: 'event_scope' }));
    expect(community.getByText('This feature is only available in OpenCTI Enterprise Edition.')).toBeTruthy();
    expect(mocks.lines).not.toHaveBeenCalled();
  });

  it('does not query a field the logs cannot be broken down by, and says so', () => {
    const { getByText } = render(makeWidget('line', { breakdownBy: 'context_data.id' }));
    expect(mocks.dashboardViz).not.toHaveBeenCalled();
    expect(getByText('This breakdown field is not available for the dataset of this widget. Edit the widget to choose another field.')).toBeTruthy();
  });
});
