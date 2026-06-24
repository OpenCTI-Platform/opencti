import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import testRender from '../../utils/tests/test-render';

// TODO(DRAFT_WORKFLOW): remove this mock when the flag is removed
vi.mock('../../utils/hooks/useHelper', () => ({
  default: () => ({
    isFeatureEnable: () => true,
  }),
}));

vi.mock('@components/common/drafts/DraftsNumber', () => ({
  default: () => <div data-testid="drafts-number" />,
}));
vi.mock('@components/common/drafts/DraftsList', () => ({
  default: () => <div data-testid="drafts-list" />,
}));
vi.mock('@components/common/drafts/DraftsDistributionList', () => ({
  default: () => <div data-testid="drafts-distribution-list" />,
}));
vi.mock('@components/common/drafts/DraftsDonut', () => ({
  default: () => <div data-testid="drafts-donut" />,
}));
vi.mock('@components/common/drafts/DraftsHorizontalBars', () => ({
  default: () => <div data-testid="drafts-horizontal-bars" />,
}));
vi.mock('@components/common/drafts/DraftsMultiVerticalBars', () => ({
  default: () => <div data-testid="drafts-multi-vertical-bars" />,
}));
vi.mock('@components/common/drafts/DraftsMultiLineChart', () => ({
  default: () => <div data-testid="drafts-multi-line-chart" />,
}));
vi.mock('@components/common/drafts/DraftsMultiAreaChart', () => ({
  default: () => <div data-testid="drafts-multi-area-chart" />,
}));
vi.mock('../../private/components/common/stix_domain_objects/StixDomainObjectBookmarksList', () => ({
  default: () => <div data-testid="bookmarks-list" />,
}));
vi.mock('../../private/components/common/stix_core_objects/StixCoreObjectsNumber', () => ({
  default: () => <div data-testid="stix-number" />,
}));
vi.mock('@components/common/stix_core_objects/StixCoreObjectsList', () => ({
  default: () => <div data-testid="stix-list" />,
}));
vi.mock('../../private/components/common/stix_core_objects/StixCoreObjectsDistributionList', () => ({
  default: () => <div data-testid="stix-distribution-list" />,
}));
vi.mock('../../private/components/common/stix_core_objects/StixCoreObjectsMultiVerticalBars', () => ({
  default: () => <div data-testid="stix-vertical-bars" />,
}));
vi.mock('../../private/components/common/stix_core_objects/StixCoreObjectsMultiLineChart', () => ({
  default: () => <div data-testid="stix-line-chart" />,
}));
vi.mock('../../private/components/common/stix_core_objects/StixCoreObjectsMultiAreaChart', () => ({
  default: () => <div data-testid="stix-area-chart" />,
}));
vi.mock('@components/common/stix_core_objects/StixCoreObjectsTimeline', () => ({
  default: () => <div data-testid="stix-timeline" />,
}));
vi.mock('../../private/components/common/stix_core_objects/StixCoreObjectsDonut', () => ({
  default: () => <div data-testid="stix-donut" />,
}));
vi.mock('@components/common/stix_core_objects/StixCoreObjectsPolarArea', () => ({
  default: () => <div data-testid="stix-polar-area" />,
}));
vi.mock('../../private/components/common/stix_core_objects/StixCoreObjectsMultiHorizontalBars', () => ({
  default: () => <div data-testid="stix-multi-horizontal-bars" />,
}));
vi.mock('../../private/components/common/stix_core_objects/StixCoreObjectsHorizontalBars', () => ({
  default: () => <div data-testid="stix-horizontal-bars" />,
}));
vi.mock('../../private/components/common/stix_core_objects/StixCoreObjectsRadar', () => ({
  default: () => <div data-testid="stix-radar" />,
}));
vi.mock('../../private/components/common/stix_core_objects/StixCoreObjectsMultiHeatMap', () => ({
  default: () => <div data-testid="stix-heatmap" />,
}));
vi.mock('../../private/components/common/stix_core_objects/StixCoreObjectsTreeMap', () => ({
  default: () => <div data-testid="stix-treemap" />,
}));
vi.mock('../../private/components/common/stix_core_objects/StixCoreObjectsWordCloud', () => ({
  default: () => <div data-testid="stix-wordcloud" />,
}));

import DashboardEntitiesViz from './DashboardEntitiesViz';
import type { Widget } from '../../utils/widget/widget';

const makeWidget = (type: string, entityTypeValues: string[] = []): Widget => ({
  id: 'w1',
  type,
  perspective: 'entities',
  dataSelection: [{
    filters: {
      mode: 'and',
      filters: entityTypeValues.length > 0
        ? [{ key: 'entity_type', values: entityTypeValues, operator: 'eq', mode: 'or' }]
        : [],
      filterGroups: [],
    },
  }],
  parameters: {},
} as unknown as Widget);

const config = { relativeDate: null, startDate: null, endDate: null };

describe('DashboardEntitiesViz', () => {
  it('renders DraftsNumber for number widget with DraftWorkspace filter', () => {
    const widget = makeWidget('number', ['DraftWorkspace']);
    const { getByTestId } = testRender(
      <DashboardEntitiesViz widget={widget} config={config} />,
    );
    expect(getByTestId('drafts-number')).toBeTruthy();
  });

  it('renders StixCoreObjectsNumber for number widget without DraftWorkspace filter', () => {
    const widget = makeWidget('number', ['Report']);
    const { getByTestId } = testRender(
      <DashboardEntitiesViz widget={widget} config={config} />,
    );
    expect(getByTestId('stix-number')).toBeTruthy();
  });

  it('renders DraftsList for list widget with DraftWorkspace filter', () => {
    const widget = makeWidget('list', ['DraftWorkspace']);
    const { getByTestId } = testRender(
      <DashboardEntitiesViz widget={widget} config={config} />,
    );
    expect(getByTestId('drafts-list')).toBeTruthy();
  });

  it('renders StixCoreObjectsList for list widget without DraftWorkspace filter', () => {
    const widget = makeWidget('list', ['Report']);
    const { getByTestId } = testRender(
      <DashboardEntitiesViz widget={widget} config={config} />,
    );
    expect(getByTestId('stix-list')).toBeTruthy();
  });

  it('renders DraftsDonut for donut widget with DraftWorkspace filter', () => {
    const widget = makeWidget('donut', ['DraftWorkspace']);
    const { getByTestId } = testRender(
      <DashboardEntitiesViz widget={widget} config={config} />,
    );
    expect(getByTestId('drafts-donut')).toBeTruthy();
  });
});
