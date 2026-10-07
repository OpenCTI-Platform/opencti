import { logApp } from '../config/conf';
import { elCreateIndex } from '../database/engine';
import { INDEX_DRAFT_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Create index draft objects';
export const up = async (next) => {
  logApp.info(`${message} > started`);
  await elCreateIndex(INDEX_DRAFT_OBJECTS);
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
