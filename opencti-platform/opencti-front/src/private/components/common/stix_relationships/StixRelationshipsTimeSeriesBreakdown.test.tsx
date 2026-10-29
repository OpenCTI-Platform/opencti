import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Mock } from 'vitest';
import { waitFor } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import type { Widget, WidgetDataSelection } from '../../../../utils/widget/widget';
import type { FilterDefinition } from '../../../../utils/hooks/useAuth';
import { daysAgo } from '../../../../utils/Time';

const mocks = vi.hoisted(() => ({
  response: {} as Record<string, unknown>,
  error: null as unknown,
  dashboardViz: vi.fn(),
  resolvedDataSelection: null as unknown[] | null,
  bars: vi.fn(),
  lines: vi.fn(),
}));

vi.mock('../../../../utils/hooks/useResizeObserver', () => ({ default: () => ({ width: 1200, height: 400 }) }));
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

import StixRelationshipsTimeSeriesBreakdown from './StixRelationshipsTimeSeriesBreakdown';

const config = { relativeDate: null, startDate: '2025-10-01T00:00:00.000Z', endDate: '2026-10-01T00:00:00.000Z' };
const host = { kind: 'workspace' } as const;
const malwares = { mode: 'and', filters: [{ key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' }], filterGroups: [] };
const sectors = { mode: 'and', filters: [{ key: 'entity_type', values: ['Sector'], operator: 'eq', mode: 'or' }], filterGroups: [] };
const targets = {
  perspective: 'relationships',
  date_attribute: 'start_time',
  // The displayed side of the widget: no part of a time series
  isTo: false,
  filters: { mode: 'and', filters: [{ key: 'relationship_type', values: ['targets'], operator: 'eq', mode: 'or' }], filterGroups: [] },
  dynamicFrom: malwares,
  dynamicTo: sectors,
} as unknown as WidgetDataSelection;
const allRelationships = { perspective: 'relationships', filters: { mode: 'and', filters: [], filterGroups: [] } } as unknown as WidgetDataSelection;

const makeWidget = (type: string, parameters: Widget['parameters'], dataSelection = targets): Widget => ({
  id: 'widget',
  type,
  perspective: 'relationships',
  dataSelection: [dataSelection],
  parameters,
});

const definition = (filterKey: string, subEntityTypes: string[]): FilterDefinition => ({
  filterKey, type: 'id', label: filterKey, multiple: true, subEntityTypes, elementsForFilterValuesSearch: [],
});
const filterKeysSchema = new Map<string, Map<string, FilterDefinition>>([
  ['stix-relationship', new Map([['objectMarking', definition('objectMarking', ['stix-relationship', 'targets'])]])],
  ['targets', new Map([['objectMarking', definition('objectMarking', ['targets'])]])],
]);
const userContext = createMockUserContext({ schema: { filterKeysSchema } });

type SerieFixture = { label: string; isOther?: boolean; entity: Record<string, unknown> | null; values: number[] };
const respond = (series: SerieFixture[], truncated = false) => {
  const days = Math.max(0, ...series.map((serie) => serie.values.length));
  const dates = Array.from({ length: days }, (_, i) => new Date(Date.UTC(2025, 9, 1 + i)).toISOString());
  mocks.response = { stixRelationshipsTimeSeriesBreakdown: { truncated, dates, series } };
};

const render = (widget: Widget) => testRender(
  <StixRelationshipsTimeSeriesBreakdown widget={widget} config={config} host={host} />,
  { userContext },
);

// The first draw of a chart can wait for the charts drawn just before it
const drawn = async (chart: Mock) => {
  await waitFor(() => expect(chart).toHaveBeenCalled());
  return chart.mock.lastCall?.[0];
};

const queryVariables = (widget: Widget, dashboardConfig: Record<string, unknown> = config) => {
  const { buildQueryVariables, dataSelection, parameters } = mocks.dashboardViz.mock.lastCall?.[0] ?? {};
  expect(dataSelection).toEqual(widget.dataSelection);
  return buildQueryVariables(dataSelection, dashboardConfig, parameters);
};

describe('StixRelationshipsTimeSeriesBreakdown', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.error = null;
  });

  it('queries the relationships of the dataset, with its dynamic source and target', () => {
    respond([]);
    const widget = makeWidget('line', { breakdownBy: 'toTypes', breakdownLimit: 20, breakdownOrder: 'asc', breakdownOther: true, interval: 'week' });
    render(widget);

    expect(mocks.dashboardViz.mock.lastCall?.[0].perspective).toEqual('relationships');
    const variables = queryVariables(widget);
    expect(variables).toMatchObject({
      field: 'toTypes',
      dateAttribute: 'start_time',
      startDate: config.startDate,
      endDate: config.endDate,
      interval: 'week',
      limit: 20,
      order: 'asc',
      includeOther: true,
      // the API checks the field against the relationship types the filters restrict to
      relationship_type: ['targets'],
    });
    expect(variables.dynamicFrom).toMatchObject({ mode: 'and', filters: [{ key: ['entity_type'], values: ['Malware'] }] });
    expect(variables.dynamicTo).toMatchObject({ mode: 'and', filters: [{ key: ['entity_type'], values: ['Sector'] }] });
    // Same restriction to the relationships the widgets display as the relationships time series
    const filters = JSON.stringify(variables.filters);
    ['targets', 'stix-core-relationship', 'stix-sighting-relationship', 'object-label', 'start_time'].forEach((value) => expect(filters).toContain(value));
    expect(variables).not.toHaveProperty('isTo');
    expect(variables).not.toHaveProperty('types');
  });

  it('breaks every relationship down without relationship type filter, and defaults a daily breakdown to the last 30 days', () => {
    respond([]);
    const widget = makeWidget('vertical-bar', { breakdownBy: 'relationship_type', interval: 'day' }, allRelationships);
    render(widget);

    const variables = queryVariables(widget, {});
    expect(variables.relationship_type).toBeNull();
    expect(variables.dateAttribute).toEqual('created_at');
    expect(variables.startDate).toEqual(daysAgo(30));
    expect(variables.endDate).toBeTruthy();
  });

  it('names the series after the translated relationship type', async () => {
    respond([
      { label: 'object', entity: null, values: [1, 2, 3] },
      { label: 'stix-sighting-relationship', entity: null, values: [1, 0, 1] },
      { label: 'not-a-translated-type', entity: null, values: [0, 0, 1] },
    ]);
    render(makeWidget('line', { breakdownBy: 'relationship_type' }, allRelationships));
    const names = (await drawn(mocks.lines)).series.map((serie: { name: string }) => serie.name);
    expect(names).toEqual(['contains', 'sighted in/at', 'not-a-translated-type']);
  });

  it('names the series after the translated type of the source or target', async () => {
    respond([
      { label: 'Intrusion-Set', entity: null, values: [2, 0, 1] },
      { label: 'Other', isOther: true, entity: null, values: [0, 1, 0] },
    ]);
    render(makeWidget('line', { breakdownBy: 'fromTypes' }));
    const { series } = await drawn(mocks.lines);
    expect(series.map((serie: { name: string }) => serie.name)).toEqual(['Intrusion Set', 'Other']);
    expect(series[0].data.map((point: { y: number }) => point.y)).toEqual([2, 0, 1]);
    expect(series[1].color).toBeTruthy();
  });

  it('names the series after the entity of an author or a marking', async () => {
    respond([{ label: 'marking-id', entity: { id: 'marking-id', entity_type: 'Marking-Definition', representative: { main: 'TLP:GREEN' } }, values: [1, 1, 1] }]);
    render(makeWidget('line', { breakdownBy: 'objectMarking' }));
    expect((await drawn(mocks.lines)).series[0].name).toEqual('TLP:GREEN');
  });

  it('warns when only the top values are displayed', () => {
    respond([{ label: 'targets', entity: null, values: [1, 2, 3] }], true);
    const { getByTestId } = render(makeWidget('line', { breakdownBy: 'relationship_type', breakdownLimit: 5 }, allRelationships));
    expect(getByTestId('widget-warning').textContent).toContain('Only the top 5 values are displayed.');
  });

  it('does not query a field the relationships do not support, and says so', () => {
    const { getByText } = render(makeWidget('line', { breakdownBy: 'objectAssignee' }));
    const { buildQueryVariables, dataSelection, parameters } = mocks.dashboardViz.mock.lastCall?.[0] ?? {};
    expect(buildQueryVariables(dataSelection, config, parameters)).toBeNull();
    expect(getByText('This breakdown field is not available for the dataset of this widget. Edit the widget to choose another field.')).toBeTruthy();
  });

  it('accepts the relationship type for a single relationship type, a type variable may resolve to one', () => {
    respond([]);
    render(makeWidget('line', { breakdownBy: 'relationship_type' }));
    const { buildQueryVariables, dataSelection, parameters } = mocks.dashboardViz.mock.lastCall?.[0] ?? {};
    expect(buildQueryVariables(dataSelection, config, parameters)).toMatchObject({ field: 'relationship_type' });
  });

  it('says why the API refused the breakdown', () => {
    // React logs the errors its boundaries catch
    vi.spyOn(console, 'error').mockImplementation(() => {});
    mocks.error = { res: { errors: [{ message: 'Time series breakdown does not support this field for these relationship types', extensions: { code: 'FUNCTIONAL_ERROR' } }] } };
    const { getByText } = render(makeWidget('line', { breakdownBy: 'toTypes' }));
    expect(getByText('This breakdown cannot be computed with the settings of this widget. Edit the widget to change them.')).toBeTruthy();
    vi.mocked(console.error).mockRestore();
  });
});
