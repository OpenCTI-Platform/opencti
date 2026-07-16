import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import { emptyFilterGroup } from 'src/utils/filters/filtersUtils';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let lastBuildQueryVariables: ((...args: any[]) => any) | undefined;

vi.mock('../../../../components/dashboard/WidgetContainer', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div data-testid="widget-container">{children}</div>,
}));

vi.mock('../../../../components/dashboard/WidgetNoData', () => ({
  default: () => <div data-testid="widget-no-data" />,
}));

vi.mock('../../../../components/dashboard/WidgetVerticalBars', () => ({
  default: () => <div data-testid="widget-vertical-bars" />,
}));

vi.mock('../../../../components/dashboard/WidgetNoHostEntity', () => ({
  default: () => <div data-testid="widget-no-host" />,
}));

vi.mock('../../../../components/Loader', () => ({
  default: () => <div data-testid="loader" />,
  LoaderVariant: { inElement: 'inElement' },
}));

vi.mock('../../../../components/dashboard/useDashboardViz', () => ({
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  default: (opts: any) => {
    lastBuildQueryVariables = opts.buildQueryVariables;
    return {
      resolvedDataSelection: [{
        filters: emptyFilterGroup,
        date_attribute: 'created_at',
      }],
      isMissingHostEntity: false,
      isPreviewMode: false,
      queryRef: null,
    };
  },
}));

vi.mock('../../../../components/dashboard/dashboard-types', () => ({}));

vi.mock('../../../../utils/hooks/useGranted', () => ({
  default: () => true,
  SETTINGS_SETACCESSES: 'SETTINGS_SETACCESSES',
}));

import StixRelationshipsMultiVerticalBars from './StixRelationshipsMultiVerticalBars';

describe('StixRelationshipsMultiVerticalBars', () => {
  const minimalProps = {
    config: { relativeDate: null, startDate: null, endDate: null },
    dataSelection: [{
      filters: emptyFilterGroup,
      date_attribute: 'created_at',
    }],
    parameters: {},
  };

  beforeEach(() => {
    lastBuildQueryVariables = undefined;
  });

  it('renders without crashing', () => {
    const { container } = testRender(<StixRelationshipsMultiVerticalBars {...minimalProps} />);
    expect(container).toBeTruthy();
  });

  it('passes configured interval to query variables', () => {
    testRender(
      <StixRelationshipsMultiVerticalBars
        {...minimalProps}
        parameters={{ interval: 'month' }}
      />,
    );
    expect(lastBuildQueryVariables).toBeDefined();
    const variables = lastBuildQueryVariables!(
      [{ filters: emptyFilterGroup, date_attribute: 'created_at' }],
      { relativeDate: null, startDate: null, endDate: null },
      { interval: 'month' },
    );
    expect(variables.interval).toBe('month');
  });

  it('defaults interval to day when not specified', () => {
    testRender(<StixRelationshipsMultiVerticalBars {...minimalProps} />);
    expect(lastBuildQueryVariables).toBeDefined();
    const variables = lastBuildQueryVariables!(
      [{ filters: emptyFilterGroup, date_attribute: 'created_at' }],
      { relativeDate: null, startDate: null, endDate: null },
      {},
    );
    expect(variables.interval).toBe('day');
  });
});
