import { logApp } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';

const message = '[MIGRATION] Remove representative field';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const updateQuery = {
    script: {
      params: { fieldToRemove: 'representative' },
      source: 'ctx._source.remove(params.fieldToRemove)',
    },
    query: {
      bool: {
        must: [{ exists: { field: 'representative' } }],
      },
    },
  };
  await elUpdateByQueryForMigration(
    message,
    READ_DATA_INDICES,
    updateQuery
  );
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
