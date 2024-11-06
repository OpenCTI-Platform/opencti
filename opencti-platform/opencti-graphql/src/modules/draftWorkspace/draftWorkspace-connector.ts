import type { Connector, ConnectorConfig } from '../../connector/internalConnector';
import { CONNECTOR_INTERNAL_INGESTION } from '../../schema/general';
import { logApp } from '../../config/conf';
import { registerConnectorQueues } from '../../database/rabbitmq';

export const DRAFT_VALIDATION_CONNECTOR_ID = 'c194e700-afb6-4c4e-ad1b-d4a00590e735';

export const DRAFT_VALIDATION_CONNECTOR: Connector = {
  id: DRAFT_VALIDATION_CONNECTOR_ID,
  internal_id: DRAFT_VALIDATION_CONNECTOR_ID,
  active: true,
  auto: false,
  connector_scope: 'draft',
  connector_type: CONNECTOR_INTERNAL_INGESTION,
  name: '[DRAFT] Draft validation',
  built_in: true,
};

export const draftValidationConnectorRuntime = async () => {
  return ({
    ...DRAFT_VALIDATION_CONNECTOR,
    configurations: [],
  });
};

const connectorConfig: ConnectorConfig = {
  id: 'DRAFT_VALIDATION_BUILT_IN_CONNECTOR',
  name: 'Draft validation built in connector',
  config: {
    enable: true,
    validate_before_import: false
  }
};

// For now, connector queues are only used to push validated bundle to worker
// This might change if we want to externalize the bundle construction to this connector
const initDraftValidationConnector = () => {
  const { config } = connectorConfig;
  const connector = DRAFT_VALIDATION_CONNECTOR;

  return {
    start: async () => {
      logApp.info(`[OPENCTI-MODULE] Starting ${connectorConfig.name} manager`);
      await registerConnectorQueues(connector.id, connector.name, connector.connector_type, connector.connector_scope);
    },
    status: () => {
      return {
        id: connectorConfig.id,
        enable: config.enable ?? false,
        running: config.enable ?? false,
      };
    },
    shutdown: async () => {
      logApp.info(`[OPENCTI-MODULE] Stopping ${connectorConfig.name} manager`);
      return true;
    },
  };
};

const draftValidationConnector = initDraftValidationConnector();

export default draftValidationConnector;
