import { screen, waitFor } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import { QueryRenderer as ReactRelayQueryRenderer, useRelayEnvironment } from 'react-relay';
import type { QueryRendererProps } from 'react-relay';
import type { CacheConfig, FetchPolicy, OperationType } from 'relay-runtime';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';

type MockQueryRendererProps = Omit<QueryRendererProps<OperationType>, 'environment'> & {
  cacheConfig?: CacheConfig | null;
  fetchPolicy?: FetchPolicy;
};

// The app-level QueryRenderer (src/relay/environment.tsx) hardcodes the singleton
// production `environment`, bypassing the RelayEnvironmentProvider context used by
// the test renderer. Mock it so it reads the mocked environment from context instead.
vi.mock('../../../../relay/environment', async () => {
  const actual = await vi.importActual<typeof import('../../../../relay/environment')>('../../../../relay/environment');
  return {
    ...actual,
    QueryRenderer: (props: MockQueryRendererProps) => {
      const environment = useRelayEnvironment();
      return <ReactRelayQueryRenderer<OperationType> environment={environment} {...props} />;
    },
  };
});

// Imported after the mock so Connector.tsx picks up the mocked QueryRenderer.
import Connector, { connectorQuery } from './Connector';
import { QueryRenderer } from '../../../../relay/environment';

// Minimal wrapper mimicking Root.jsx: fetches the connector then renders the component under test.
const ConnectorTestWrapper = ({ connectorId }: { connectorId: string }) => (
  <QueryRenderer
    query={connectorQuery}
    variables={{ id: connectorId }}
    render={({ props }: { props: { connector?: unknown } | null }) => {
      if (props?.connector) {
        return <Connector connector={props.connector as never} />;
      }
      return null;
    }}
  />
);

const baseMockConnector = {
  id: 'connector-id',
  name: 'My connector',
  title: 'My connector',
  active: true,
  auto: false,
  only_contextual: false,
  connector_trigger_filters: null,
  connector_type: 'EXTERNAL_IMPORT',
  connector_scope: ['Report'],
  connector_state: '',
  is_managed: false,
  manager_current_status: null,
  manager_contract_definition: null,
  manager_contract_excerpt: null,
  catalog_identity: null,
  catalog_slug_manual: null,
  built_in: false,
  connector_info: null,
  connector_user: null,
  connector_queue_details: null,
  manager_connector_logs: [],
  manager_connector_uptime: null,
  manager_health_metrics: null,
  config: null,
  updated_at: '2024-01-01T00:00:00.000Z',
  created_at: '2024-01-01T00:00:00.000Z',
};

describe('Connector', () => {
  it('should display the Version field with its value before the State field', async () => {
    const { relayEnv } = testRender(<ConnectorTestWrapper connectorId="connector-id" />, {
      userContext: createMockUserContext({
        schema: {
          scos: [],
          sdos: [],
          smos: [],
          scrs: [],
          schemaRelationsTypesMapping: new Map(),
          schemaRelationsRefTypesMapping: new Map(),
          filterKeysSchema: new Map(),
        },
      }),
    });

    await waitFor(() => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        Connector: () => ({ ...baseMockConnector, version: '6.7.17' }),
      }));
    });

    await waitFor(() => {
      expect(screen.getByText('Version')).toBeTruthy();
    });
    expect(screen.getByText('6.7.17')).toBeTruthy();

    // Version must be displayed before State in the Details panel.
    const versionLabel = screen.getByText('Version');
    const stateLabel = screen.getByText('State');
    expect(versionLabel.compareDocumentPosition(stateLabel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('should display an empty placeholder when no version is provided', async () => {
    const { relayEnv } = testRender(<ConnectorTestWrapper connectorId="connector-id" />, {
      userContext: createMockUserContext({
        schema: {
          scos: [],
          sdos: [],
          smos: [],
          scrs: [],
          schemaRelationsTypesMapping: new Map(),
          schemaRelationsRefTypesMapping: new Map(),
          filterKeysSchema: new Map(),
        },
      }),
    });

    await waitFor(() => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        Connector: () => ({ ...baseMockConnector, version: null }),
      }));
    });

    await waitFor(() => {
      expect(screen.getByText('Version')).toBeTruthy();
    });
    // Both Version and State fields render an empty placeholder, so scope
    // the assertion to the Version field's container.
    const versionLabel = screen.getByText('Version');
    const versionContainer = versionLabel.closest('.MuiGrid-item');
    expect(versionContainer?.textContent).toContain('-');
  });

  describe('catalog identity of a self-deployed connector', () => {
    const emptySchema = {
      scos: [],
      sdos: [],
      smos: [],
      scrs: [],
      schemaRelationsTypesMapping: new Map(),
      schemaRelationsRefTypesMapping: new Map(),
      filterKeysSchema: new Map(),
    };
    const connectorAdmin = {
      id: 'admin-id',
      name: 'admin',
      user_email: 'admin@opencti.io',
      language: 'en-us',
      theme: 'default',
      capabilities: [{ name: 'BYPASS' }],
      userSubscriptions: { edges: [] },
    };

    const renderConnector = (connector: Record<string, unknown>, me?: unknown) => {
      const { relayEnv } = testRender(<ConnectorTestWrapper connectorId="connector-id" />, {
        userContext: createMockUserContext({
          schema: emptySchema,
          me,
          // The connector actions shown to an administrator read the sensitive configuration.
          settings: { platform_protected_sensitive_config: { enabled: false } },
        }),
      });
      return waitFor(() => {
        relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
          Connector: () => ({ ...baseMockConnector, connector_queue_details: { messages_number: 0, messages_size: 0 }, ...connector }),
        }));
      });
    };

    it('should show the logo and the catalog entry the connector was identified as', async () => {
      await renderConnector({
        name: 'Abuse.ch URLhaus',
        catalog_identity: { slug: 'urlhaus', title: 'URLhaus', logo: '/logo/urlhaus.png', short_description: 'Malicious URLs', source: 'name' },
      }, connectorAdmin);

      await waitFor(() => {
        expect(screen.getByText('About this connector')).toBeTruthy();
      });
      expect(screen.getByAltText('Abuse.ch URLhaus').getAttribute('src')).toBe('/logo/urlhaus.png');
      expect(screen.getByText('URLhaus')).toBeTruthy();
      expect(screen.getByText('Malicious URLs')).toBeTruthy();
      expect(screen.getByText('Identified by name')).toBeTruthy();
      expect(screen.getByRole('link', { name: 'View in catalog' }).getAttribute('href')).toBe('/dashboard/integrations/catalog/urlhaus');
      expect(screen.getByRole('button', { name: 'Change catalog entry' })).toBeTruthy();
    });

    it('should name the catalog entry chosen for a connector whose name says otherwise', async () => {
      await renderConnector({
        name: 'Feed A',
        catalog_identity: { slug: 'mitre-atlas', title: 'MITRE ATLAS', logo: '/logo/atlas.png', short_description: null, source: 'manual' },
      }, connectorAdmin);

      await waitFor(() => {
        expect(screen.getByText('Chosen by hand')).toBeTruthy();
      });
      expect(screen.getByText('Feed A')).toBeTruthy();
      expect(screen.getByText('MITRE ATLAS')).toBeTruthy();
    });

    it('should not repeat a catalog title equal to the connector name', async () => {
      await renderConnector({
        name: 'URLhaus',
        catalog_identity: { slug: 'urlhaus', title: 'URLhaus', logo: '/logo/urlhaus.png', short_description: 'Malicious URLs', source: 'reported' },
      }, connectorAdmin);

      await waitFor(() => {
        expect(screen.getByText('Malicious URLs')).toBeTruthy();
      });
      // Only the page header carries the name.
      expect(screen.getAllByText('URLhaus')).toHaveLength(1);
    });

    it('should show the label of the connector type in the basic information', async () => {
      await renderConnector({ connector_type: 'INTERNAL_ENRICHMENT', catalog_identity: null }, connectorAdmin);

      await waitFor(() => {
        expect(screen.getByText('Basic information')).toBeTruthy();
      });
      // Page header and basic information name the type the same way.
      expect(screen.getAllByText('Internal enrichment')).toHaveLength(2);
      expect(screen.queryByText('INTERNAL_ENRICHMENT')).toBeNull();
    });

    it('should offer to identify a connector the platform could not recognise', async () => {
      await renderConnector({ name: 'In-house feed', catalog_identity: null }, connectorAdmin);

      await waitFor(() => {
        expect(screen.getByText('This connector is not linked to a catalog entry.')).toBeTruthy();
      });
      expect(screen.getByRole('button', { name: 'Identify connector' })).toBeTruthy();
      expect(screen.queryByAltText('In-house feed')).toBeNull();
    });

    it('should not offer the manual choice to a user who cannot manage connectors', async () => {
      await renderConnector({
        name: 'Abuse.ch URLhaus',
        catalog_identity: { slug: 'urlhaus', title: 'URLhaus', logo: '/logo/urlhaus.png', short_description: null, source: 'reported' },
      });

      await waitFor(() => {
        expect(screen.getByText('Reported by the connector')).toBeTruthy();
      });
      expect(screen.queryByRole('button', { name: 'Change catalog entry' })).toBeNull();
    });

    it('should hide the prompt from a user who cannot manage connectors', async () => {
      await renderConnector({ name: 'In-house feed', catalog_identity: null });

      await waitFor(() => {
        expect(screen.getByText('Version')).toBeTruthy();
      });
      expect(screen.queryByText('This connector is not linked to a catalog entry.')).toBeNull();
    });
  });
});
