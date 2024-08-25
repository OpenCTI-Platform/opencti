import { logApp } from '../config/conf';
import { listAllEntities } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_INGESTION_CSV, ENTITY_TYPE_INGESTION_RSS, ENTITY_TYPE_INGESTION_TAXII } from '../modules/ingestion/ingestion-types';
import { registerConnectorForIngestion } from '../domain/connector';

const message = '[MIGRATION] Ingestion dedicated built in connector creation';

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info(`${message} > started`);
  // CSV
  const csvIngests = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_INGESTION_CSV]);
  for (let index = 0; index < csvIngests.length; index += 1) {
    const element = csvIngests[index];
    await registerConnectorForIngestion(context, 'CSV', element.id, element.name, element.ingestion_running);
  }
  // RSS
  const rssIngests = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_INGESTION_RSS]);
  for (let index = 0; index < rssIngests.length; index += 1) {
    const element = rssIngests[index];
    await registerConnectorForIngestion(context, 'RSS', element.id, element.name, element.ingestion_running);
  }
  // TAXII
  const taxiiIngests = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_INGESTION_TAXII]);
  for (let index = 0; index < taxiiIngests.length; index += 1) {
    const element = taxiiIngests[index];
    await registerConnectorForIngestion(context, 'TAXII', element.id, element.name, element.ingestion_running);
  }
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
