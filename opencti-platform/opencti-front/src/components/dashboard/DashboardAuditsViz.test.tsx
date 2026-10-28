import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../utils/tests/test-render';

const flags = vi.hoisted(() => ({ enabled: ['TIME_SERIES_BREAKDOWN'] }));
vi.mock('../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: (flag: string) => flags.enabled.includes(flag) }),
}));

vi.mock('@components/common/audits/AuditsNumber', () => ({
  default: () => <div data-testid="audits-number" />,
}));
vi.mock('@components/common/audits/AuditsList', () => ({
  default: () => <div data-testid="audits-list" />,
}));
vi.mock('@components/common/audits/AuditsDistributionList', () => ({
  default: () => <div data-testid="audits-distribution-list" />,
}));
vi.mock('@components/common/audits/AuditsMultiVerticalBars', () => ({
  default: () => <div data-testid="audits-vertical-bars" />,
}));
vi.mock('@components/common/audits/AuditsMultiLineChart', () => ({
  default: () => <div data-testid="audits-line-chart" />,
}));
vi.mock('@components/common/audits/AuditsMultiAreaChart', () => ({
  default: () => <div data-testid="audits-area-chart" />,
}));
vi.mock('@components/common/audits/AuditsDonut', () => ({
  default: () => <div data-testid="audits-donut" />,
}));
vi.mock('@components/common/audits/AuditsPolarArea', () => ({
  default: () => <div data-testid="audits-polar-area" />,
}));
vi.mock('@components/common/audits/AuditsHorizontalBars', () => ({
  default: () => <div data-testid="audits-horizontal-bars" />,
}));
vi.mock('@components/common/audits/AuditsRadar', () => ({
  default: () => <div data-testid="audits-radar" />,
}));
vi.mock('@components/common/audits/AuditsMultiHeatMap', () => ({
  default: () => <div data-testid="audits-heatmap" />,
}));
vi.mock('@components/common/audits/AuditsTreeMap', () => ({
  default: () => <div data-testid="audits-treemap" />,
}));
vi.mock('@components/common/audits/AuditsWordCloud', () => ({
  default: () => <div data-testid="audits-wordcloud" />,
}));
vi.mock('@components/common/audits/AuditsTimeSeriesBreakdown', () => ({
  default: () => <div data-testid="audits-time-series-breakdown" />,
}));

import DashboardAuditsViz from './DashboardAuditsViz';
import type { Widget } from '../../utils/widget/widget';

const makeWidget = (type: string, parameters: Widget['parameters'] = {}, unique = false): Widget => ({
  id: 'w1',
  type,
  perspective: 'audits',
  dataSelection: [{ attribute: 'user_id', unique, filters: { mode: 'and', filters: [], filterGroups: [] } }],
  parameters,
} as unknown as Widget);

const config = { relativeDate: null, startDate: null, endDate: null };
const workspace = { kind: 'workspace' } as const;
const withBreakdown = { breakdownBy: 'event_scope' };

describe('DashboardAuditsViz', () => {
  it('renders every audits time series widget of a workspace as a breakdown', () => {
    ['vertical-bar', 'line', 'area', 'heatmap'].forEach((type) => {
      const { getByTestId, unmount } = testRender(
        <DashboardAuditsViz widget={makeWidget(type, withBreakdown)} config={config} host={workspace} />,
      );
      expect(getByTestId('audits-time-series-breakdown')).toBeTruthy();
      unmount();
    });
  });

  it('keeps the regular widget without breakdown', () => {
    const { getByTestId } = testRender(<DashboardAuditsViz widget={makeWidget('line')} config={config} host={workspace} />);
    expect(getByTestId('audits-line-chart')).toBeTruthy();
  });

  it('ignores a leftover breakdown on a widget that cannot be broken down', () => {
    const donut = testRender(<DashboardAuditsViz widget={makeWidget('donut', withBreakdown)} config={config} host={workspace} />);
    expect(donut.getByTestId('audits-donut')).toBeTruthy();
    donut.unmount();
    // A breakdown counts every event, distinct values are counted without it
    const distinct = testRender(<DashboardAuditsViz widget={makeWidget('line', withBreakdown, true)} config={config} host={workspace} />);
    expect(distinct.getByTestId('audits-line-chart')).toBeTruthy();
  });

  it('only renders breakdowns in workspace dashboards', () => {
    const customView = { kind: 'custom-view' as const, customViewTargetEntityType: 'Report' };
    const { getByTestId } = testRender(<DashboardAuditsViz widget={makeWidget('area', withBreakdown)} config={config} host={customView} />);
    expect(getByTestId('audits-area-chart')).toBeTruthy();
  });

  describe('without the TIME_SERIES_BREAKDOWN feature flag', () => {
    beforeEach(() => {
      flags.enabled = [];
    });
    afterEach(() => {
      flags.enabled = ['TIME_SERIES_BREAKDOWN'];
    });

    it('renders the regular widget, whatever breakdown it carries', () => {
      const charts: Record<string, string> = { 'vertical-bar': 'audits-vertical-bars', line: 'audits-line-chart', area: 'audits-area-chart', heatmap: 'audits-heatmap' };
      Object.entries(charts).forEach(([type, testId]) => {
        const { getByTestId, queryByTestId, unmount } = testRender(
          <DashboardAuditsViz widget={makeWidget(type, withBreakdown)} config={config} host={workspace} />,
        );
        expect(getByTestId(testId)).toBeTruthy();
        expect(queryByTestId('audits-time-series-breakdown')).toBeNull();
        unmount();
      });
    });
  });
});
