import { logApp } from '../config/conf';
import { listAllEntities } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_INGESTION_CSV, ENTITY_TYPE_INGESTION_RSS, ENTITY_TYPE_INGESTION_TAXII } from '../modules/ingestion/ingestion-types';
import { registerConnectorForIngestion } from '../domain/connector';

const message = '[MIGRATION] Ingestion dedicated built in connector creation';

const generateConnectorInput = async (context, type, element) => {
  const connector = {
    id: element.id,
    type,
    name: element.name,
    is_running: element.ingestion_running ?? false,
    connector_user_id: element.user_id,
  };
  return registerConnectorForIngestion(context, connector);
};

const generateConnectorsForIngestEntityType = async (context, entityType, connectorType) => {
  const csvIngests = await listAllEntities(context, SYSTEM_USER, [entityType]);
  for (let index = 0; index < csvIngests.length; index += 1) {
    const element = csvIngests[index];
    await generateConnectorInput(context, connectorType, element);
  }
};

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info(`${message} > started`);
  await generateConnectorsForIngestEntityType(context, ENTITY_TYPE_INGESTION_CSV, 'CSV');
  await generateConnectorsForIngestEntityType(context, ENTITY_TYPE_INGESTION_RSS, 'RSS');
  await generateConnectorsForIngestEntityType(context, ENTITY_TYPE_INGESTION_TAXII, 'TAXII');
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
