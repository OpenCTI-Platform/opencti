import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';

vi.mock('../../../../relay/environment', () => ({
  APP_BASE_PATH: '',
  MESSAGING$: { messages$: { subscribe: () => ({}) } },
  environment: {},
  fetchQuery: vi.fn(),
}));

vi.mock('../../../../components/dashboard/WidgetContainer', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div data-testid="widget-container">{children}</div>,
}));

vi.mock('../../../../components/dashboard/WidgetNoData', () => ({
  default: () => <div data-testid="widget-no-data" />,
}));

vi.mock('../../../../components/dashboard/WidgetNumber', () => ({
  default: () => <div data-testid="widget-number" />,
}));

vi.mock('../../../../components/Loader', () => ({
  default: () => <div data-testid="loader" />,
  LoaderVariant: { inElement: 'inElement' },
}));

vi.mock('../../../../components/dashboard/useDashboardViz', () => ({
  default: ({ dataSelection }: { dataSelection: unknown[] }) => ({
    resolvedDataSelection: dataSelection,
    isMissingHostEntity: false,
    isMissingSavedFilters: false,
    isPreviewMode: false,
    queryRef: null,
  }),
}));

vi.mock('../../../../components/dashboard/WidgetRenderContent', () => ({
  default: ({ queryRef, children }: { queryRef: unknown; children: React.ReactNode }) => (
    queryRef ? <>{children}</> : <div data-testid="loader" />
  ),
}));

vi.mock('../../../../components/dashboard/dashboardVizUtils', () => ({
  computeStartEndDates: () => ({ startDate: null, endDate: null }),
}));

vi.mock('../../../../components/dashboard/WidgetNoHostEntity', () => ({
  default: () => <div data-testid="widget-no-host" />,
}));

vi.mock('../../../../utils/hooks/useEntityTranslation', () => ({
  default: () => ({ translateEntityType: (s: string) => s }),
}));

import DraftsNumber from './DraftsNumber';
import { emptyFilterGroup } from 'src/utils/filters/filtersUtils';

describe('DraftsNumber', () => {
  const minimalProps = {
    config: { relativeDate: null, startDate: null, endDate: null },
    dataSelection: [{
      filters: emptyFilterGroup,
      date_attribute: 'created_at',
    }],
    parameters: {},
  };

  it('renders without crashing', () => {
    const { container } = testRender(<DraftsNumber {...minimalProps} />);
    expect(container).toBeTruthy();
  });

  it('shows loader while queryRef is null', () => {
    const { getByTestId } = testRender(<DraftsNumber {...minimalProps} />);
    expect(getByTestId('loader')).toBeTruthy();
  });
});
