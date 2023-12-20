import { logApp } from '../config/conf';
import { elCreateIndex, engineMappingGenerator } from '../database/engine';
import { INDEX_FILES } from '../database/utils';

const message = '[MIGRATION] Create index files';
export const up = async (next) => {
  logApp.info(`${message} > started`);
  const mappingProperties = engineMappingGenerator();
  await elCreateIndex(INDEX_FILES, mappingProperties);
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
