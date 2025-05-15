import { logMigration } from '../config/conf';
import { elCreateIndex, engineMappingGenerator } from '../database/engine';
import { INDEX_PIR_RELS } from '../database/utils';

const message = '[MIGRATION] Create index for PIR meta re';
export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const mappingProperties = engineMappingGenerator();
  await elCreateIndex(INDEX_PIR_RELS, mappingProperties);
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
