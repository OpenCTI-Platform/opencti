import { logApp } from '../config/conf';
import { elCreateIndex, elIndexExists, engineMappingGenerator } from '../database/engine';
import { INDEX_SEARCH } from '../database/utils';

const message = '[MIGRATION] Create missing search index';
export const up = async (next) => {
  logApp.info(`${message} > started`);
  if (!await elIndexExists(INDEX_SEARCH)) {
    logApp.info(`${message} > creating missing index`);
    const mappingProperties = engineMappingGenerator();
    await elCreateIndex(INDEX_SEARCH, mappingProperties);
  }
  next();
};

export const down = async (next) => {
  next();
};
