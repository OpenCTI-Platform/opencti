import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../utils/tests/test-render';
import type { Widget } from '../../utils/widget/widget';

const flags = vi.hoisted(() => ({ enabled: ['TIME_SERIES_BREAKDOWN'] }));
vi.mock('../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: (flag: string) => flags.enabled.includes(flag) }),
}));

vi.mock('../../private/components/common/stix_relationships/StixRelationshipsNumber', () => ({
  default: () => <div data-testid="relationships-number" />,
}));
vi.mock('../../private/components/common/stix_relationships/StixRelationshipsList', () => ({
  default: () => <div data-testid="relationships-list" />,
}));
vi.mock('../../private/components/common/stix_relationships/StixRelationshipsDistributionList', () => ({
  default: () => <div data-testid="relationships-distribution-list" />,
}));
vi.mock('../../private/components/common/stix_relationships/StixRelationshipsMultiVerticalBars', () => ({
  default: () => <div data-testid="relationships-vertical-bars" />,
}));
vi.mock('../../private/components/common/stix_relationships/StixRelationshipsMultiLineChart', () => ({
  default: () => <div data-testid="relationships-line-chart" />,
}));
vi.mock('../../private/components/common/stix_relationships/StixRelationshipsMultiAreaChart', () => ({
  default: () => <div data-testid="relationships-area-chart" />,
}));
vi.mock('@components/common/stix_relationships/StixRelationshipsTimeline', () => ({
  default: () => <div data-testid="relationships-timeline" />,
}));
vi.mock('@components/common/stix_relationships/StixRelationshipsDonut', () => ({
  default: () => <div data-testid="relationships-donut" />,
}));
vi.mock('@components/common/stix_relationships/StixRelationshipsMultiHorizontalBars/StixRelationshipsMultiHorizontalBars', () => ({
  default: () => <div data-testid="relationships-multi-horizontal-bars" />,
}));
vi.mock('../../private/components/common/stix_relationships/StixRelationshipsHorizontalBars', () => ({
  default: () => <div data-testid="relationships-horizontal-bars" />,
}));
vi.mock('../../private/components/common/stix_relationships/StixRelationshipsRadar', () => ({
  default: () => <div data-testid="relationships-radar" />,
}));
vi.mock('../../private/components/common/stix_relationships/StixRelationshipsPolarArea', () => ({
  default: () => <div data-testid="relationships-polar-area" />,
}));
vi.mock('../../private/components/common/stix_relationships/StixRelationshipsMultiHeatMap', () => ({
  default: () => <div data-testid="relationships-heatmap" />,
}));
vi.mock('../../private/components/common/stix_relationships/StixRelationshipsTreeMap', () => ({
  default: () => <div data-testid="relationships-tree" />,
}));
vi.mock('../../private/components/common/stix_relationships/StixRelationshipsMap', () => ({
  default: () => <div data-testid="relationships-map" />,
}));
vi.mock('../../private/components/common/stix_relationships/StixRelationshipsWordCloud', () => ({
  default: () => <div data-testid="relationships-wordcloud" />,
}));
vi.mock('../../private/components/common/stix_relationships/StixRelationshipsTimeSeriesBreakdown', () => ({
  default: () => <div data-testid="relationships-time-series-breakdown" />,
}));

import DashboardRelationshipsViz from './DashboardRelationshipsViz';

const makeWidget = (type: string, parameters: Widget['parameters'] = {}, datasetPerspective: Widget['perspective'] = 'relationships'): Widget => ({
  id: 'widget',
  type,
  perspective: 'relationships',
  dataSelection: [{
    perspective: datasetPerspective,
    filters: { mode: 'and', filters: [{ key: 'relationship_type', values: ['targets'], operator: 'eq', mode: 'or' }], filterGroups: [] },
  }],
  parameters,
});
const config = { relativeDate: null, startDate: null, endDate: null };
const workspace = { kind: 'workspace' } as const;

describe('DashboardRelationshipsViz', () => {
  describe('breakdown', () => {
    const withBreakdown = { breakdownBy: 'toTypes' };
    const charts: Record<string, string> = { 'vertical-bar': 'vertical-bars', line: 'line-chart', area: 'area-chart', heatmap: 'heatmap' };

    it('renders every relationships time series widget of a workspace as a breakdown', () => {
      Object.keys(charts).forEach((type) => {
        const { getByTestId, unmount } = testRender(
          <DashboardRelationshipsViz widget={makeWidget(type, withBreakdown)} config={config} host={workspace} />,
        );
        expect(getByTestId('relationships-time-series-breakdown')).toBeTruthy();
        unmount();
      });
    });

    it('renders the relationships time series of a custom view as a breakdown too', () => {
      const customView = { kind: 'custom-view' as const, customViewTargetEntityType: 'Report' };
      const { getByTestId } = testRender(<DashboardRelationshipsViz widget={makeWidget('line', withBreakdown)} config={config} host={customView} />);
      expect(getByTestId('relationships-time-series-breakdown')).toBeTruthy();
    });

    it('keeps the regular widget without breakdown, in a fintel template or with an entities dataset', () => {
      Object.entries(charts).forEach(([type, testId]) => {
        const regular = testRender(<DashboardRelationshipsViz widget={makeWidget(type)} config={config} host={workspace} />);
        expect(regular.getByTestId(`relationships-${testId}`)).toBeTruthy();
        regular.unmount();
        const fintelTemplate = { kind: 'fintelTemplate' as const, fintelWidgets: [], fintelEntityType: 'Report', fintelEditorValue: '' };
        const inFintelTemplate = testRender(<DashboardRelationshipsViz widget={makeWidget(type, withBreakdown)} config={config} host={fintelTemplate} />);
        expect(inFintelTemplate.getByTestId(`relationships-${testId}`)).toBeTruthy();
        inFintelTemplate.unmount();
        const entities = testRender(<DashboardRelationshipsViz widget={makeWidget(type, withBreakdown, 'entities')} config={config} host={workspace} />);
        expect(entities.getByTestId(`relationships-${testId}`)).toBeTruthy();
        entities.unmount();
      });
    });

    it('ignores a leftover breakdown on a widget that cannot be broken down', () => {
      const { getByTestId } = testRender(
        <DashboardRelationshipsViz widget={makeWidget('donut', withBreakdown)} config={config} host={workspace} />,
      );
      expect(getByTestId('relationships-donut')).toBeTruthy();
    });

    describe('without the TIME_SERIES_BREAKDOWN feature flag', () => {
      beforeEach(() => {
        flags.enabled = [];
      });
      afterEach(() => {
        flags.enabled = ['TIME_SERIES_BREAKDOWN'];
      });

      it('renders the regular widget, whatever breakdown it carries', () => {
        Object.entries(charts).forEach(([type, testId]) => {
          const { getByTestId, queryByTestId, unmount } = testRender(
            <DashboardRelationshipsViz widget={makeWidget(type, withBreakdown)} config={config} host={workspace} />,
          );
          expect(getByTestId(`relationships-${testId}`)).toBeTruthy();
          expect(queryByTestId('relationships-time-series-breakdown')).toBeNull();
          unmount();
        });
      });
    });
  });
});
