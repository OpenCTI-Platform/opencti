import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import { emptyFilterGroup } from 'src/utils/filters/filtersUtils';

vi.mock('../../../../components/dashboard/WidgetContainer', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div data-testid="widget-container">{children}</div>,
}));

vi.mock('../../../../components/dashboard/WidgetNoData', () => ({
  default: () => <div data-testid="widget-no-data" />,
}));

vi.mock('../../../../components/dashboard/WidgetDonut', () => ({
  default: () => <div data-testid="widget-donut" />,
}));

vi.mock('../../../../components/dashboard/useDashboardViz', () => ({
  default: () => ({
    resolvedDataSelection: [{
      filters: emptyFilterGroup,
      attribute: 'entity_type',
      date_attribute: 'created_at',
    }],
    isMissingHostEntity: false,
    isMissingSavedFilters: false,
    isPreviewMode: false,
    queryRef: null,
  }),
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

import DraftsDonut from './DraftsDonut';

describe('DraftsDonut', () => {
  const minimalProps = {
    config: { relativeDate: null, startDate: null, endDate: null },
    dataSelection: [{
      filters: emptyFilterGroup,
      attribute: 'entity_type',
      date_attribute: 'created_at',
    }],
    parameters: {},
  };

  it('renders without crashing', () => {
    const { container } = testRender(<DraftsDonut {...minimalProps} />);
    expect(container).toBeTruthy();
  });

  it('shows loader when queryRef is null', () => {
    const { getByTestId } = testRender(<DraftsDonut {...minimalProps} />);
    expect(getByTestId('loader')).toBeTruthy();
  });
});
