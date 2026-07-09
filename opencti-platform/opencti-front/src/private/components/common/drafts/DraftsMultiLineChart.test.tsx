import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';

let capturedVariables: Record<string, unknown> | null = null;

vi.mock('../../../../relay/environment', () => ({
  APP_BASE_PATH: '',
  fileUri: (f: string) => f,
  MESSAGING$: { messages$: { subscribe: () => ({}) } },
  environment: {},
  QueryRenderer: ({ render, variables }: { render: (args: { props: null }) => React.ReactNode; variables: Record<string, unknown> }) => {
    capturedVariables = variables;
    return render({ props: null });
  },
  fetchQuery: vi.fn(),
}));

vi.mock('../../../../components/dashboard/WidgetContainer', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div data-testid="widget-container">{children}</div>,
}));

vi.mock('../../../../components/dashboard/WidgetNoData', () => ({
  default: () => <div data-testid="widget-no-data" />,
}));

vi.mock('../../../../components/dashboard/WidgetMultiLines', () => ({
  default: () => <div data-testid="widget-multi-lines" />,
}));

vi.mock('../../../../components/Loader', () => ({
  default: () => <div data-testid="loader" />,
  LoaderVariant: { inElement: 'inElement' },
}));

vi.mock('../../../../components/dashboard/DashboardRefreshContext', () => ({
  useDashboardRefreshToken: () => null,
}));

vi.mock('../../../../components/dashboard/useDashboardViz', () => ({
  default: ({ dataSelection }: { dataSelection: unknown[] }) => ({
    resolvedDataSelection: dataSelection,
    isMissingHostEntity: false,
    isPreviewMode: false,
  }),
}));

vi.mock('../../../../components/dashboard/dashboardVizUtils', () => ({
  computeStartEndDates: () => ({ startDate: null, endDate: null }),
}));

vi.mock('../../../../components/dashboard/WidgetNoHostEntity', () => ({
  default: () => <div data-testid="widget-no-host" />,
}));

import DraftsMultiLineChart from './DraftsMultiLineChart';
import { emptyFilterGroup } from 'src/utils/filters/filtersUtils';

describe('DraftsMultiLineChart', () => {
  const minimalProps = {
    config: { relativeDate: null, startDate: null, endDate: null },
    dataSelection: [{
      filters: emptyFilterGroup,
      date_attribute: 'created_at',
    }],
    parameters: {},
  };

  it('renders without crashing', () => {
    const { container } = testRender(<DraftsMultiLineChart {...minimalProps} />);
    expect(container).toBeTruthy();
  });

  it('shows loader while data is loading', () => {
    const { getByTestId } = testRender(<DraftsMultiLineChart {...minimalProps} />);
    expect(getByTestId('loader')).toBeTruthy();
  });

  it('falls back to monthsAgo(12) and now() when computeStartEndDates returns null', () => {
    testRender(<DraftsMultiLineChart {...minimalProps} />);
    expect(capturedVariables).toBeDefined();
    expect(capturedVariables?.startDate).toBeTruthy();
    expect(capturedVariables?.endDate).toBeTruthy();
  });
});
