import { logMigration } from '../config/conf';
import { elDeleteIndex } from '../database/engine';
import { ES_INDEX_PREFIX } from '../database/utils';

const message = '[MIGRATION] Delete index for PIR meta rel';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  await elDeleteIndex(`${ES_INDEX_PREFIX}_pir_relationships-000001`);
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
