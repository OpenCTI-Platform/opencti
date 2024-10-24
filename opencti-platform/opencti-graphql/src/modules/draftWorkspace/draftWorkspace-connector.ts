import type { Connector, ConnectorConfig } from '../../connector/internalConnector';
import { CONNECTOR_INTERNAL_IMPORT_FILE } from '../../schema/general';
import { logApp } from '../../config/conf';
import { registerConnectorQueues } from '../../database/rabbitmq';

export const DRAFT_VALIDATION_CONNECTOR_ID = 'c194e700-afb6-4c4e-ad1b-d4a00590e735';

export const DRAFT_VALIDATION_CONNECTOR: Connector = {
  id: DRAFT_VALIDATION_CONNECTOR_ID,
  internal_id: DRAFT_VALIDATION_CONNECTOR_ID,
  active: true,
  auto: false,
  connector_scope: 'text/json',
  connector_type: CONNECTOR_INTERNAL_IMPORT_FILE,
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

const initDraftValidationConnector = () => {
  const { config } = connectorConfig;
  const connector = DRAFT_VALIDATION_CONNECTOR;
  let rabbitMqConnection: { close: () => void };

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
      if (rabbitMqConnection) rabbitMqConnection.close();
      return true;
    },
  };
};

const draftValidationConnector = initDraftValidationConnector();

export default draftValidationConnector;
