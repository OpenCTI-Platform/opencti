import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import IngestionCatalogConnector from './IngestionCatalogConnector';
import type { IngestionConnector } from './types';

const queryData = vi.hoisted(() => ({ current: {} as Record<string, unknown> }));

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    graphql: vi.fn((query) => query),
    usePreloadedQuery: vi.fn(() => queryData.current),
  };
});
vi.mock('../../../../utils/hooks/useQueryLoading', () => ({ default: vi.fn(() => ({})) }));
vi.mock('../../../../utils/hooks/useConnectedDocumentModifier', () => ({ default: vi.fn(() => ({ setTitle: vi.fn() })) }));
vi.mock('../../../../utils/hooks/useEnterpriseEdition', () => ({ default: vi.fn(() => true) }));
vi.mock('@components/data/connectors/ConnectorManagerStatusContext', () => ({
  ConnectorManagerStatusProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useConnectorManagerStatus: vi.fn(() => ({ hasActiveManagers: true })),
}));
vi.mock('@components/data/connectors/ConnectorDeploymentBanner', () => ({ default: () => null }));
vi.mock('../../../../components/Breadcrumbs', () => ({ default: () => null }));
vi.mock('@components/integrations/catalog/IngestionCatalogConnectorHeader', () => ({ default: () => null }));
vi.mock('@components/integrations/catalog/IngestionCatalogConnectorOverview', () => ({ default: () => null }));
vi.mock('@components/integrations/catalog/IngestionCatalogConnectorCreation', () => ({
  default: ({ connector }: { connector: IngestionConnector }) => <div data-testid="creation-panel">{connector.title}</div>,
}));

const buildContract = (compatibility: IngestionConnector['compatibility']) => ({
  contract: {
    catalog_id: 'catalog-1',
    contract: JSON.stringify({
      title: 'Redpanda',
      slug: 'redpanda',
      manager_supported: true,
      container_image: 'opencti/connector-redpanda',
      compatibility,
    }),
  },
  connectors: [],
});

describe('IngestionCatalogConnector', () => {
  beforeEach(() => {
    window.history.pushState({}, '', '/');
  });

  it('opens the deployment dialog once when redirected with openConfig', () => {
    queryData.current = buildContract({
      is_compatible: true,
      latest_compatible_version: '7.260828.0',
      minimum_platform_version: null,
      maximum_platform_version: null,
    });

    testRender(<IngestionCatalogConnector />, { route: '/?openConfig=true' });

    expect(screen.getByTestId('creation-panel')).toHaveTextContent('Redpanda');
  });

  it('does not open the deployment dialog of a connector that is not compatible with the platform version', () => {
    queryData.current = buildContract({
      is_compatible: false,
      latest_compatible_version: null,
      minimum_platform_version: '7.261000.0',
      maximum_platform_version: null,
    });

    testRender(<IngestionCatalogConnector />, { route: '/?openConfig=true' });

    expect(screen.queryByTestId('creation-panel')).not.toBeInTheDocument();
  });
});
