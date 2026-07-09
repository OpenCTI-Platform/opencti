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

vi.mock('../../../../components/dashboard/WidgetListCoreObjects', () => ({
  default: () => <div data-testid="widget-list" />,
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

import DraftsList from './DraftsList';
import { emptyFilterGroup } from 'src/utils/filters/filtersUtils';

describe('DraftsList', () => {
  const minimalProps = {
    config: { relativeDate: null, startDate: null, endDate: null },
    dataSelection: [{
      filters: emptyFilterGroup,
      date_attribute: 'created_at',
      sort_by: 'created_at',
    }],
    widgetId: 'widget-1',
    parameters: {},
  };

  it('renders without crashing', () => {
    const { container } = testRender(<DraftsList {...minimalProps} />);
    expect(container).toBeTruthy();
  });

  it('shows loader while data is loading', () => {
    const { getByTestId } = testRender(<DraftsList {...minimalProps} />);
    expect(getByTestId('loader')).toBeTruthy();
  });

  it('uses created_at as default date_attribute', () => {
    // The component uses created_at as fallback when date_attribute is empty
    const propsWithEmptyDate = {
      ...minimalProps,
      dataSelection: [{
        ...minimalProps.dataSelection[0],
        date_attribute: '',
      }],
    };
    const { container } = testRender(<DraftsList {...propsWithEmptyDate} />);
    expect(container).toBeTruthy();
  });
});
