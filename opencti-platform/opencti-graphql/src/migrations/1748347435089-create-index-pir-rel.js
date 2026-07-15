import { logMigration } from '../config/conf';
import { elCreateIndex } from '../database/engine';
import { ES_INDEX_PREFIX } from '../database/utils';

const message = '[MIGRATION] Create index for PIR meta re';
export const up = async (next) => {
  logMigration.info(`${message} > started`);
  await elCreateIndex(`${ES_INDEX_PREFIX}_pir_relationships`);
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
