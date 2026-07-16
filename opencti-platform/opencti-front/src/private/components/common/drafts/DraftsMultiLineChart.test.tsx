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

vi.mock('../../../../components/dashboard/WidgetMultiLines', () => ({
  default: () => <div data-testid="widget-multi-lines" />,
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
      isMissingSavedFilters: false,
      isPreviewMode: false,
      queryRef: null,
    };
  },
}));

vi.mock('../../../../components/dashboard/WidgetRenderContent', () => ({
  default: ({ children, queryRef }: { children: React.ReactNode; queryRef: unknown }) => (
    queryRef ? <>{children}</> : <div data-testid="loader" />
  ),
}));

vi.mock('../../../../components/dashboard/dashboardVizUtils', () => ({
  computeStartEndDates: () => ({ startDate: null, endDate: null }),
}));

vi.mock('../../../../utils/hooks/useGranted', () => ({
  default: () => true,
  SETTINGS_SETACCESSES: 'SETTINGS_SETACCESSES',
}));

import DraftsMultiLineChart from './DraftsMultiLineChart';

describe('DraftsMultiLineChart', () => {
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
    const { container } = testRender(<DraftsMultiLineChart {...minimalProps} />);
    expect(container).toBeTruthy();
  });

  it('shows loader when queryRef is null', () => {
    const { getByTestId } = testRender(<DraftsMultiLineChart {...minimalProps} />);
    expect(getByTestId('loader')).toBeTruthy();
  });

  it('falls back to monthsAgo(12) and now() when computeStartEndDates returns null', () => {
    testRender(<DraftsMultiLineChart {...minimalProps} />);
    expect(lastBuildQueryVariables).toBeDefined();
    const variables = lastBuildQueryVariables!(
      [{ filters: emptyFilterGroup, date_attribute: 'created_at' }],
      { relativeDate: null, startDate: null, endDate: null },
      {},
    );
    expect(variables.startDate).toBeTruthy();
    expect(variables.endDate).toBeTruthy();
    expect(typeof variables.startDate).toBe('string');
    expect(typeof variables.endDate).toBe('string');
  });
});
