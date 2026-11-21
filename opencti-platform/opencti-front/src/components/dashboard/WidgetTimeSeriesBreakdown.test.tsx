import React, { Suspense } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, waitFor } from '@testing-library/react';
import { useLazyLoadQuery } from 'react-relay';
import type { ConcreteRequest, OperationType, Variables } from 'relay-runtime';
import testRender from '../../utils/tests/test-render';
import WidgetTimeSeriesBreakdown from './WidgetTimeSeriesBreakdown';
import type { WidgetTimeSeriesBreakdown_breakdown$key } from './__generated__/WidgetTimeSeriesBreakdown_breakdown.graphql';
import entitiesQuery from '../../private/components/common/stix_core_objects/__generated__/StixCoreObjectsTimeSeriesBreakdownQuery.graphql';
import relationshipsQuery from '../../private/components/common/stix_relationships/__generated__/StixRelationshipsTimeSeriesBreakdownQuery.graphql';
import auditsQuery from '../../private/components/common/audits/__generated__/AuditsTimeSeriesBreakdownQuery.graphql';
import publicEntitiesQuery from '../../public/components/dashboard/stix_core_objects/__generated__/PublicStixCoreObjectsTimeSeriesBreakdownQuery.graphql';
import publicRelationshipsQuery from '../../public/components/dashboard/stix_relationships/__generated__/PublicStixRelationshipsTimeSeriesBreakdownQuery.graphql';

const mocks = vi.hoisted(() => ({ lines: vi.fn() }));

vi.mock('../../utils/hooks/useResizeObserver', () => ({ default: () => ({ width: 1200, height: 400 }) }));
vi.mock('./WidgetMultiLines', () => ({
  default: (props: unknown) => {
    mocks.lines(props);
    return <div data-testid="lines" />;
  },
}));

const privateVariables = { field: 'objectLabel', startDate: '2025-10-01T00:00:00.000Z', interval: 'day' };
const publicVariables = { uriKey: 'public-key', widgetId: 'widget' };

// The five queries that spread the fragment of the widget, with the field of their response that holds the breakdown.
// The public breakdowns give the interval of their dates, the others do not.
const queries: { name: string; query: ConcreteRequest; field: string; variables: Variables; interval: string | null }[] = [
  { name: 'entities', query: entitiesQuery, field: 'stixCoreObjectsTimeSeriesBreakdown', variables: privateVariables, interval: null },
  { name: 'relationships', query: relationshipsQuery, field: 'stixRelationshipsTimeSeriesBreakdown', variables: privateVariables, interval: null },
  { name: 'audits', query: auditsQuery, field: 'auditsTimeSeriesBreakdown', variables: privateVariables, interval: null },
  { name: 'public entities', query: publicEntitiesQuery, field: 'publicStixCoreObjectsTimeSeriesBreakdown', variables: publicVariables, interval: 'month' },
  { name: 'public relationships', query: publicRelationshipsQuery, field: 'publicStixRelationshipsTimeSeriesBreakdown', variables: publicVariables, interval: 'month' },
];

// The response of the API, as it comes over the wire: the abstract types the entity implements are told by the
// keys Relay asks for (__isBasicObject, __isStixObject)
const values = [1, 0, 2];
const response = (interval: string | null) => ({
  truncated: false,
  interval,
  dates: ['2025-10-01T00:00:00.000Z', '2025-11-01T00:00:00.000Z', '2025-12-01T00:00:00.000Z'],
  series: [
    {
      label: 'label-id',
      isOther: false,
      entity: {
        __typename: 'Label',
        __isBasicObject: 'Label',
        __isStixObject: 'Label',
        id: 'label-id',
        entity_type: 'Label',
        representative: { main: 'malicious' },
        color: '#ff0000',
      },
      values,
    },
    {
      label: 'marking-id',
      isOther: false,
      entity: {
        __typename: 'MarkingDefinition',
        __isBasicObject: 'MarkingDefinition',
        __isStixObject: 'MarkingDefinition',
        id: 'marking-id',
        entity_type: 'Marking-Definition',
        representative: { main: 'TLP:RED' },
        x_opencti_color: '#c62828',
      },
      values,
    },
    { label: 'user-id', isOther: false, entity: { __typename: 'Creator', id: 'user-id', name: 'Alice' }, values },
    {
      label: 'group-id',
      isOther: false,
      entity: { __typename: 'Group', __isBasicObject: 'Group', id: 'group-id', entity_type: 'Group', name: 'Analysts' },
      values,
    },
    { label: 'Other', isOther: true, entity: null, values },
  ],
});

const Breakdown = ({ query, field, variables }: { query: ConcreteRequest; field: string; variables: Variables }) => {
  const data = useLazyLoadQuery<OperationType>(query, variables) as Record<string, WidgetTimeSeriesBreakdown_breakdown$key | null>;
  return (
    <WidgetTimeSeriesBreakdown
      breakdown={data[field]}
      type="line"
      parameters={{ breakdownBy: 'objectLabel', interval: 'day' }}
      onMounted={vi.fn()}
      onWarningChange={vi.fn()}
    />
  );
};

describe('WidgetTimeSeriesBreakdown', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it.each(queries)('reads the breakdown of the $name query through its fragment', async ({ query, field, variables, interval }) => {
    const { relayEnv } = testRender(
      <Suspense fallback={null}>
        <Breakdown query={query} field={field} variables={variables} />
      </Suspense>,
    );
    await act(async () => relayEnv.mock.resolveMostRecentOperation({ data: { [field]: response(interval) } }));

    await waitFor(() => expect(mocks.lines).toHaveBeenCalled());
    const lines = mocks.lines.mock.lastCall?.[0];
    // Every entity is named, the ones without representative included
    expect(lines.series.map((serie: { name: string }) => serie.name)).toEqual(['malicious', 'TLP:RED', 'Alice', 'Analysts', 'Other']);
    // A label and a marking keep their own colors
    expect(lines.series[0].color).toEqual('#ff0000');
    expect(lines.series[1].color).toEqual('#c62828');
    expect(lines.series[0].data).toEqual([
      { x: new Date('2025-10-01T00:00:00.000Z'), y: 1 },
      { x: new Date('2025-11-01T00:00:00.000Z'), y: 0 },
      { x: new Date('2025-12-01T00:00:00.000Z'), y: 2 },
    ]);
    // Dates in the interval the API counted them in, or else in the requested one
    expect(lines.interval).toEqual(interval ?? 'day');
  });
});
