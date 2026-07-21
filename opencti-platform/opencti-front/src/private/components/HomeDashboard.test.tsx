import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../utils/tests/test-render';
import HomeDashboard from './HomeDashboard';
import { XTM_HUB_PERMISSION_REQUIRED_QUERY_PARAM } from './RedirectByPath';

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    createFragmentContainer: (component: React.ComponentType) => component,
    graphql: vi.fn((query) => query),
    usePreloadedQuery: vi.fn(() => ({
      me: {
        id: 'me-id',
        default_dashboard: { id: 'custom-dashboard' },
        default_time_field: 'created_at',
      },
      workspace: {
        id: 'custom-dashboard',
        name: 'Custom dashboard',
      },
    })),
    useFragment: vi.fn((_fragment, data) => data),
  };
});

vi.mock('../../utils/hooks/useQueryLoading', () => ({
  default: vi.fn(() => ({})),
}));

vi.mock('../../utils/hooks/useConnectedDocumentModifier', () => ({
  default: vi.fn(() => ({ setTitle: vi.fn() })),
}));

vi.mock('../../utils/hooks/useLocalStorage', () => ({
  usePaginationLocalStorage: vi.fn(() => ({ viewStorage: {} })),
}));

vi.mock('../../components/i18n', () => ({
  default: (component: React.ComponentType) => component,
  inject18n: (component: React.ComponentType) => component,
  useFormatter: () => ({
    t_i18n: (value: string) => value,
  }),
}));

vi.mock('../../utils/Security', () => ({
  default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

vi.mock('./HomeDashboardSettings', () => ({
  PLATFORM_DASHBOARD: 'platform-dashboard',
}));

vi.mock('./workspaces/dashboards/CustomDashboard', () => ({
  default: () => <div data-testid="custom-dashboard" />,
}));

vi.mock('./common/stix_relationships/StixRelationshipsDistributionList', () => ({
  default: () => null,
}));
vi.mock('./common/stix_relationships/StixRelationshipsPolarArea', () => ({
  default: () => null,
}));
vi.mock('./common/stix_core_objects/StixCoreObjectsList', () => ({
  default: () => null,
}));
vi.mock('./common/stix_relationships/StixRelationshipsMultiAreaChart', () => ({
  default: () => null,
}));
vi.mock('./common/stix_core_objects/StixCoreObjectsNumber', () => ({
  default: () => null,
}));
vi.mock('./common/location/LocationMiniMapTargets', () => ({
  default: () => null,
}));
vi.mock('./common/stix_relationships/StixRelationshipsHorizontalBars', () => ({
  default: () => null,
}));

describe('HomeDashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('opens permission dialog and removes permission-required query param', async () => {
    const userContext = createMockUserContext({
      me: {
        ...createMockUserContext().me,
        default_dashboards: [{ id: 'platform-dashboard' }],
      },
    });

    const { user } = testRender(<HomeDashboard />, {
      route: `/dashboard?foo=bar&${XTM_HUB_PERMISSION_REQUIRED_QUERY_PARAM}=true`,
      userContext,
    });

    expect(await screen.findByText('Permission required')).toBeInTheDocument();
    expect(screen.getByText('You do not have permission to connect this product. Please contact your product administrator to connect the product on your behalf.')).toBeInTheDocument();

    await waitFor(() => {
      expect(window.location.search).toBe('?foo=bar');
    });

    await user.click(screen.getByRole('button', { name: 'Close' }));

    await waitFor(() => {
      expect(screen.queryByText('Permission required')).not.toBeInTheDocument();
    });
  });
});
