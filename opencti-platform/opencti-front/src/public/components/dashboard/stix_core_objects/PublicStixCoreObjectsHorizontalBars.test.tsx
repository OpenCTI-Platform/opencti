import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';

/**
 * A public dashboard is served to anonymous visitors. Any redirection it
 * offers points at a private page, so the click lands on the login screen --
 * decision D4: public dashboards carry no navigation at all.
 */
vi.mock('../../../../components/dashboard/WidgetContainer', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock('../../../../components/dashboard/WidgetNoData', () => ({
  default: () => <div data-testid="widget-no-data" />,
}));

vi.mock('../../../../components/dashboard/WidgetHorizontalBars', () => ({
  default: (props: Record<string, unknown>) => (
    <div
      data-testid="bars"
      data-redirection={String(!!props.redirectionUtils)}
      data-drilldown={String(!!props.drilldown)}
    />
  ),
}));

vi.mock('../usePublicDashboardViz', () => ({ default: () => ({}) }));

vi.mock('react-relay', async (importOriginal) => ({
  ...(await importOriginal<typeof import('react-relay')>()),
  usePreloadedQuery: () => ({
    publicStixCoreObjectsDistribution: [{ label: 'Malware', value: 4, entity: { id: 'malware-1', entity_type: 'Malware' } }],
  }),
}));

// eslint-disable-next-line import/first
import PublicStixCoreObjectsHorizontalBars from './PublicStixCoreObjectsHorizontalBars';

describe('PublicStixCoreObjectsHorizontalBars', () => {
  const props = {
    uriKey: 'public-key',
    startDate: null,
    endDate: null,
    widget: {
      id: 'widget-1',
      parameters: {},
      dataSelection: [{ filters: emptyFilterGroup, attribute: 'entity_type' }],
    },
  };

  it('offers neither a redirection nor a drill-down to an anonymous visitor', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    testRender(<PublicStixCoreObjectsHorizontalBars {...(props as any)} />);

    const bars = screen.getByTestId('bars');
    expect(bars.dataset.redirection).toBe('false');
    expect(bars.dataset.drilldown).toBe('false');
  });
});
