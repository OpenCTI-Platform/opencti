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

// Public manifests keep one entry per dataset but strip its filters
const makeWidget = (overrides: Partial<Widget> = {}): Widget => ({
  id: 'public-widget-1',
  type: 'line',
  perspective: 'entities',
  dataSelection: [{ label: 'Reports' }],
  parameters: {},
  ...overrides,
} as unknown as Widget);

const renderEntityWidget = (widget: Widget) => {
  const { hook } = testRenderHook(() => usePublicDashboardWidgets('public-key', {
    relativeDate: null,
    startDate: null,
    endDate: null,
  }));
  return testRender(<>{hook.result.current.entityWidget(widget)}</>);
};

describe('usePublicDashboardWidgets', () => {
  it('should render a broken down widget with the breakdown component', () => {
    const { getByTestId, queryByTestId } = renderEntityWidget(makeWidget({
      parameters: { breakdownBy: 'creator', interval: 'month' },
    }));

    expect(getByTestId('breakdown').textContent).toEqual('public-key/public-widget-1');
    expect(queryByTestId('line')).toBeNull();
  });

  it('should keep rendering a widget without breakdown as before', () => {
    const { getByTestId, queryByTestId } = renderEntityWidget(makeWidget({ parameters: { interval: 'month' } }));

    expect(getByTestId('line')).toBeTruthy();
    expect(queryByTestId('breakdown')).toBeNull();
  });
});
