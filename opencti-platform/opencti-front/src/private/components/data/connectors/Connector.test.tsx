import { screen, waitFor } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import { QueryRenderer as ReactRelayQueryRenderer, useRelayEnvironment } from 'react-relay';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';

// The app-level QueryRenderer (src/relay/environment.tsx) hardcodes the singleton
// production `environment`, bypassing the RelayEnvironmentProvider context used by
// the test renderer. Mock it so it reads the mocked environment from context instead.
vi.mock('../../../../relay/environment', async () => {
  const actual = await vi.importActual<typeof import('../../../../relay/environment')>('../../../../relay/environment');
  return {
    ...actual,
    QueryRenderer: (props: Record<string, unknown>) => {
      const environment = useRelayEnvironment();
      return <ReactRelayQueryRenderer environment={environment} {...props} />;
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
});
