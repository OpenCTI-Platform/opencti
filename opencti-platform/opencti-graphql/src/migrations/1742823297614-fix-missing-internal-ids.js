import { logApp } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';

const message = '[MIGRATION] add internal_id for entities that have not this field';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const updateQuery = {
    script: {
      source: 'ctx._source.internal_id = ctx._id; ',
    },
    query: {
      bool: {
        must_not: [{ exists: { field: 'internal_id' } }],
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
