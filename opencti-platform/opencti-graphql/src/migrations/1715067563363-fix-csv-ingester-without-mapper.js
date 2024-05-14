import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { listAllEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_INGESTION_CSV } from '../modules/ingestion/ingestion-types';
import { elDeleteElements, elFindByIds } from '../database/engine';

const message = '[MIGRATION] delete CSV feeds that have inexisting CSV mapper';

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info(`${message} > started`);

  const allIngesters = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_INGESTION_CSV]);
  const mappersUsedIds = allIngesters.map((ingester) => ingester.csv_mapper_id);
  const mappersUsedAndValid = await elFindByIds(context, SYSTEM_USER, mappersUsedIds, { baseData: true });
  const mappersUsedAndValidIds = mappersUsedAndValid.map((mapper) => mapper.id);

  const ingestersToDelete = allIngesters.filter((ingester) => !mappersUsedAndValidIds.includes(ingester.csv_mapper_id));

  if (ingestersToDelete.length === 0) {
    logApp.info(`${message} > no invalid CSV feed detected`);
  } else {
    logApp.info(`${message} > deleting ${ingestersToDelete.length} IngestionCSV objects`);
    await elDeleteElements(context, SYSTEM_USER, ingestersToDelete);
  }
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
