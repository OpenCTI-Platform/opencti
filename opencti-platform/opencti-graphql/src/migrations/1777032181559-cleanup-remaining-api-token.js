import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Cleanup remaining api_token field on users';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  // Remove any remaining api_token field on User documents.
  const updateQuery = {
    script: {
      lang: 'painless',
      source: "ctx._source.remove('api_token')",
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'User' } } },
          { exists: { field: 'api_token' } },
        ],
      },
    },
  };
  await elUpdateByQueryForMigration(message, [READ_INDEX_INTERNAL_OBJECTS], updateQuery);
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
