import React from 'react';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router';
import Integrations from './Integrations';

const mocks = vi.hoisted(() => ({
  useQueryLoader: vi.fn(),
  loadCatalogs: vi.fn(),
  loadDeployment: vi.fn(),
  loadFeeds: vi.fn(),
  loadForms: vi.fn(),
}));

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    graphql: vi.fn((query) => query),
    useQueryLoader: mocks.useQueryLoader,
  };
});

vi.mock('@components/data/connectors/ConnectorManagerStatusContext', () => ({
  ConnectorManagerStatusProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useConnectorManagerStatus: () => ({ hasActiveManagers: false }),
}));

vi.mock('@components/data/connectors/ConnectorDeploymentBanner', () => ({
  default: () => null,
}));

vi.mock('@components/integrations/catalog/IngestionConnectorsCatalog', () => ({
  __esModule: true,
  default: () => null,
  ingestionConnectorsCatalogsQuery: {},
}));

vi.mock('@components/integrations/catalog/IngestionConnectors', () => ({
  __esModule: true,
  default: () => null,
  ingestionConnectorsQuery: {},
}));

vi.mock('@components/integrations/deployed/IngestionFeeds', () => ({
  __esModule: true,
  IngestionFeeds: () => null,
  IngestionFeedsForms: () => null,
  ingestionFeedsFormsQuery: {},
  ingestionFeedsQuery: {},
}));

vi.mock('@components/integrations/components/MarketplaceUi', () => ({
  BrowseMoreButton: () => null,
}));

vi.mock('@components/integrations/available/IntegrationsAvailable', () => ({
  default: () => null,
}));

vi.mock('@components/integrations/deployed/IntegrationsDeployed', () => ({
  default: () => null,
}));

vi.mock('@components/integrations/deployed/IntegrationsStatsStrip', () => ({
  default: () => null,
}));

vi.mock('@components/integrations/deployed/useDeployedIntegrations', () => ({
  connectorIdFromIngestId: (id: string) => id,
}));

vi.mock('../../../components/Breadcrumbs', () => ({
  default: () => null,
}));

vi.mock('../../../components/i18n', () => ({
  useFormatter: () => ({
    t_i18n: (value: string) => value,
  }),
}));

vi.mock('../../../components/Loader', () => ({
  __esModule: true,
  default: () => <div data-testid="loader" />,
  LoaderVariant: { container: 'container' },
}));

vi.mock('../../../components/PageContainer', () => ({
  default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

vi.mock('../../../utils/hooks/useConnectedDocumentModifier', () => ({
  default: () => ({ setTitle: vi.fn() }),
}));

vi.mock('../../../utils/hooks/useGranted', () => ({
  __esModule: true,
  default: () => true,
  INGESTION: 'INGESTION',
  KNOWLEDGE_KNASKIMPORT: 'KNOWLEDGE_KNASKIMPORT',
  KNOWLEDGE_KNUPDATE: 'KNOWLEDGE_KNUPDATE',
  MODULES: 'MODULES',
}));

vi.mock('./paperSurface', () => ({
  paperBg: () => 'transparent',
  paperBorder: () => 'transparent',
}));

vi.mock('@filigran/design-system', () => ({
  Tabs: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  TabsList: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  TabsTrigger: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

describe('Integrations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.useQueryLoader
      .mockReturnValueOnce([null, mocks.loadCatalogs])
      .mockReturnValueOnce([null, mocks.loadDeployment])
      .mockReturnValueOnce([null, mocks.loadFeeds])
      .mockReturnValueOnce([null, mocks.loadForms]);
  });

  it('refreshes catalogs from the network on mount', async () => {
    render(
      <MemoryRouter initialEntries={['/dashboard/integrations/available']}>
        <Routes>
          <Route path="/dashboard/integrations/:tab" element={<Integrations />} />
        </Routes>
      </MemoryRouter>,
    );

    await waitFor(() => {
      expect(mocks.loadCatalogs).toHaveBeenCalledWith({}, { fetchPolicy: 'store-and-network' });
    });
  });
});
