import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';

vi.mock('../../../../relay/environment', () => ({
  APP_BASE_PATH: '',
  fileUri: (f: string) => f,
  MESSAGING$: { messages$: { subscribe: () => ({}) } },
  environment: {},
  QueryRenderer: ({ render }: { render: (args: { props: null }) => React.ReactNode }) => render({ props: null }),
  fetchQuery: vi.fn(),
}));

vi.mock('../../../../components/dashboard/WidgetContainer', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div data-testid="widget-container">{children}</div>,
}));

vi.mock('../../../../components/dashboard/WidgetNoData', () => ({
  default: () => <div data-testid="widget-no-data" />,
}));

vi.mock('../../../../components/dashboard/WidgetDonut', () => ({
  default: () => <div data-testid="widget-donut" />,
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

vi.mock('../../../../components/dashboard/dashboard-viz-utils', () => ({
  computeStartEndDates: () => ({ startDate: null, endDate: null }),
}));

vi.mock('../../../../components/dashboard/WidgetNoHostEntity', () => ({
  default: () => <div data-testid="widget-no-host" />,
}));

import DraftsDonut from './DraftsDonut';

describe('DraftsDonut', () => {
  const minimalProps = {
    config: { relativeDate: null, startDate: null, endDate: null },
    dataSelection: [{
      filters: { mode: 'and' as const, filters: [], filterGroups: [] },
      attribute: 'entity_type',
      date_attribute: 'created_at',
    }],
    parameters: {},
  };

  it('renders without crashing', () => {
    const { container } = testRender(<DraftsDonut {...minimalProps} />);
    expect(container).toBeTruthy();
  });

  it('shows loader while data is loading', () => {
    const { getByTestId } = testRender(<DraftsDonut {...minimalProps} />);
    expect(getByTestId('loader')).toBeTruthy();
  });
});
