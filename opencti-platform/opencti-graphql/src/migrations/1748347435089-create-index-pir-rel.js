import { logMigration } from '../config/conf';
import { elCreateIndex, engineMappingGenerator } from '../database/engine';
import { ES_INDEX_PREFIX } from '../database/utils';

const message = '[MIGRATION] Create index for PIR meta re';
export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const mappingProperties = engineMappingGenerator();
  await elCreateIndex(`${ES_INDEX_PREFIX}_pir_relationships`, mappingProperties);
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
