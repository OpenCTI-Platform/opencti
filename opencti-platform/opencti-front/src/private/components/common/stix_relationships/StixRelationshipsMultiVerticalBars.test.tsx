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

vi.mock('../../../../components/dashboard/WidgetRenderContent', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div data-testid="widget-render-content">{children}</div>,
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

vi.mock('../../../../components/dashboard/dashboard-types', () => ({}));

import StixRelationshipsMultiVerticalBars from './StixRelationshipsMultiVerticalBars';

describe('StixRelationshipsMultiVerticalBars', () => {
  const minimalProps = {
    dataSelection: [{
      filters: emptyFilterGroup,
      date_attribute: 'created_at',
    }],
    config: {
      startDate: '2025-01-01T00:00:00Z',
      endDate: '2025-12-31T23:59:59Z',
    },
  };

  beforeEach(() => {
    lastBuildQueryVariables = undefined;
  });

  it('renders without crashing', () => {
    const { getByTestId } = testRender(
      <StixRelationshipsMultiVerticalBars
        {...minimalProps}
        parameters={{}}
      />,
    );
    expect(getByTestId('widget-container')).toBeDefined();
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
      minimalProps.dataSelection,
      minimalProps.config,
      { interval: 'month' },
    );
    expect(variables.interval).toBe('month');
  });

  it('defaults interval to day when not specified', () => {
    testRender(
      <StixRelationshipsMultiVerticalBars
        {...minimalProps}
        parameters={{}}
      />,
    );
    expect(lastBuildQueryVariables).toBeDefined();
    const variables = lastBuildQueryVariables!(
      minimalProps.dataSelection,
      minimalProps.config,
      {},
    );
    expect(variables.interval).toBe('day');
  });
});
