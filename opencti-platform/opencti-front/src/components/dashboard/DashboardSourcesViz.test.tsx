import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import testRender from '../../utils/tests/test-render';

vi.mock('@components/common/sources/SourcesNumber', () => ({
  default: () => <div data-testid="sources-number" />,
}));
vi.mock('@components/common/sources/SourcesDistribution', () => ({
  default: ({ widgetType }: { widgetType: string }) => <div data-testid="sources-distribution">{widgetType}</div>,
}));
vi.mock('@components/common/sources/SourcesTimeSeries', () => ({
  default: () => <div data-testid="sources-time-series" />,
}));
vi.mock('@components/common/sources/SourcesBubble', () => ({
  default: () => <div data-testid="sources-bubble" />,
}));
vi.mock('./WidgetNotImplemented', () => ({
  default: () => <div data-testid="widget-not-implemented" />,
}));

import DashboardSourcesViz from './DashboardSourcesViz';
import type { Widget } from '../../utils/widget/widget';

const makeWidget = (type: string): Widget => ({
  id: 'w1',
  type,
  perspective: 'sources',
  dataSelection: [{ attribute: 'value_score', filters: { mode: 'and', filters: [], filterGroups: [] } }],
  parameters: {},
} as unknown as Widget);

const config = { relativeDate: null, startDate: null, endDate: null };

describe('DashboardSourcesViz', () => {
  it('renders SourcesNumber for a number widget', () => {
    const { getByTestId } = testRender(<DashboardSourcesViz widget={makeWidget('number')} config={config} />);
    expect(getByTestId('sources-number')).toBeTruthy();
  });

  it.each(['list', 'distribution-list', 'horizontal-bar', 'donut'])('renders SourcesDistribution with the widget type for a %s widget', (type) => {
    const { getByTestId } = testRender(<DashboardSourcesViz widget={makeWidget(type)} config={config} />);
    expect(getByTestId('sources-distribution').textContent).toEqual(type);
  });

  it('renders SourcesTimeSeries for a line widget', () => {
    const { getByTestId } = testRender(<DashboardSourcesViz widget={makeWidget('line')} config={config} />);
    expect(getByTestId('sources-time-series')).toBeTruthy();
  });

  it('renders SourcesBubble for a bubble widget', () => {
    const { getByTestId } = testRender(<DashboardSourcesViz widget={makeWidget('bubble')} config={config} />);
    expect(getByTestId('sources-bubble')).toBeTruthy();
  });

  it('renders the not implemented placeholder for an unsupported widget type', () => {
    const { getByTestId, queryByTestId } = testRender(<DashboardSourcesViz widget={makeWidget('radar')} config={config} />);
    expect(getByTestId('widget-not-implemented')).toBeTruthy();
    expect(queryByTestId('sources-number')).toBeNull();
  });
});
