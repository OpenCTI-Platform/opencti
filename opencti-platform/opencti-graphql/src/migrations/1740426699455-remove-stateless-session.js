import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';

const message = '[MIGRATION] Remove stateless_session in Users';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const updateQuery = {
    script: {
      params: { fieldToRemove: 'stateless_session' },
      source: 'ctx._source.remove(params.fieldToRemove)',
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'User' } } },
        ],
      },
    },
  };
  await elUpdateByQueryForMigration(
    message,
    READ_INDEX_INTERNAL_OBJECTS,
    updateQuery,
  );
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
