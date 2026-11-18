export const mitreConnector = {
  id: 'mitre-connector-id',
  internal_id: 'mitre-connector-id',
  standard_id: 'connector--11111111-2222-4333-8444-555555555555',
  entity_type: 'Connector',
  name: 'mitre',
  title: 'MITRE',
  catalog_id: 'filigran-catalog',
  manager_contract_image: 'opencti/connector-mitre',
  manager_requested_status: 'started',
  connector_state: '{"last_run": 1700000000}',
  connector_user_id: 'mitre-user-id',
  manager_contract: {
    config_schema: {
      type: 'object',
      properties: {
        OPENCTI_TOKEN: { type: 'string' },
        MITRE_INTERVAL: { type: 'integer', description: 'Interval in days' },
        MITRE_API_KEY: { type: 'string', format: 'password', description: 'The key of the MITRE API' },
        MITRE_PROXY_TOKEN: { type: 'string', description: 'A token for the proxy' },
      },
      required: ['MITRE_API_KEY'],
    },
  },
  manager_contract_configuration: [
    { key: 'OPENCTI_TOKEN', value: 'runtime-token' },
    { key: 'MITRE_INTERVAL', value: '7' },
    { key: 'MITRE_API_KEY', value: 'encrypted-secret', encrypted: true },
  ],
};

// A connector registered from outside the platform: no catalog, never listed
export const externalConnector = {
  id: 'external-connector-id',
  internal_id: 'external-connector-id',
  standard_id: 'connector--aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
  entity_type: 'Connector',
  name: 'external',
  title: 'External',
  connector_user_id: 'external-user-id',
};

export const ALL_CONNECTORS = [mitreConnector, externalConnector];

export const mitreConnectorUser = { id: 'mitre-user-id', internal_id: 'mitre-user-id', user_confidence_level: { max_confidence: 75, overrides: [] } };
