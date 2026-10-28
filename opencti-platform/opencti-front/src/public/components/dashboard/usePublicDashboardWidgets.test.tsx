import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import testRender, { testRenderHook } from '../../../utils/tests/test-render';
import usePublicDashboardWidgets from './usePublicDashboardWidgets';
import type { Widget } from '../../../utils/widget/widget';

vi.mock('./stix_core_objects/PublicStixCoreObjectsTimeSeriesBreakdown', () => ({
  default: ({ uriKey, widget }: { uriKey: string; widget: Widget }) => (
    <div data-testid="breakdown">{`${uriKey}/${widget.id}`}</div>
  ),
}));
vi.mock('./stix_core_objects/PublicStixCoreObjectsMultiLineChart', () => ({
  default: () => <div data-testid="line" />,
}));
vi.mock('./stix_relationships/PublicStixRelationshipsTimeSeriesBreakdown', () => ({
  default: ({ uriKey, widget }: { uriKey: string; widget: Widget }) => (
    <div data-testid="relationships-breakdown">{`${uriKey}/${widget.id}`}</div>
  ),
}));
vi.mock('./stix_relationships/PublicStixRelationshipsMultiLineChart', () => ({
  default: () => <div data-testid="relationships-line" />,
}));

// Public manifests keep one entry per dataset but strip its filters
const makeWidget = (overrides: Partial<Widget> = {}): Widget => ({
  id: 'public-widget-1',
  type: 'line',
  perspective: 'entities',
  dataSelection: [{ label: 'Reports' }],
  parameters: {},
  ...overrides,
} as unknown as Widget);

const renderWidget = (widget: Widget, kind: 'entityWidget' | 'relationshipWidget') => {
  const { hook } = testRenderHook(() => usePublicDashboardWidgets('public-key', {
    relativeDate: null,
    startDate: null,
    endDate: null,
  }));
  return testRender(<>{hook.result.current[kind](widget)}</>);
};
const renderEntityWidget = (widget: Widget) => renderWidget(widget, 'entityWidget');

describe('usePublicDashboardWidgets', () => {
  it('should render a broken down widget with the breakdown component', () => {
    const { getByTestId, queryByTestId } = renderEntityWidget(makeWidget({
      parameters: { breakdownBy: 'creator', interval: 'month' },
    }));

    expect(getByTestId('breakdown').textContent).toEqual('public-key/public-widget-1');
    expect(queryByTestId('line')).toBeNull();
  });

  it('should keep refusing an audits widget, even broken down', () => {
    const { hook } = testRenderHook(() => usePublicDashboardWidgets('public-key', { relativeDate: null, startDate: null, endDate: null }));
    const widget = makeWidget({ perspective: 'audits', parameters: { breakdownBy: 'event_scope', interval: 'month' } });
    const { getByText, queryByTestId } = testRender(<>{hook.result.current.auditWidget(widget)}</>);

    expect(getByText('Audits are not supported in public dashboards')).toBeTruthy();
    expect(queryByTestId('breakdown')).toBeNull();
  });

  it('should keep rendering a widget without breakdown as before', () => {
    const { getByTestId, queryByTestId } = renderEntityWidget(makeWidget({ parameters: { interval: 'month' } }));

    expect(getByTestId('line')).toBeTruthy();
    expect(queryByTestId('breakdown')).toBeNull();
  });

  it('should render a broken down relationships widget with the relationships breakdown component', () => {
    const relationships = makeWidget({ perspective: 'relationships', parameters: { breakdownBy: 'toTypes', interval: 'day' } });
    const { getByTestId, queryByTestId } = renderWidget(relationships, 'relationshipWidget');

    expect(getByTestId('relationships-breakdown').textContent).toEqual('public-key/public-widget-1');
    expect(queryByTestId('relationships-line')).toBeNull();
  });

  it('should keep rendering a relationships widget without breakdown as before', () => {
    const relationships = makeWidget({ perspective: 'relationships', parameters: { interval: 'day' } });
    const { getByTestId, queryByTestId } = renderWidget(relationships, 'relationshipWidget');

    expect(getByTestId('relationships-line')).toBeTruthy();
    expect(queryByTestId('relationships-breakdown')).toBeNull();
  });
});
