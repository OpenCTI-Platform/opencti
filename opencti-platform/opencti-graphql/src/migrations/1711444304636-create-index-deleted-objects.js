import { logApp } from '../config/conf';
import { elCreateIndex } from '../database/engine';
import { INDEX_DELETED_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Create index deleted objects';
export const up = async (next) => {
  logApp.info(`${message} > started`);
  await elCreateIndex(INDEX_DELETED_OBJECTS);
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
