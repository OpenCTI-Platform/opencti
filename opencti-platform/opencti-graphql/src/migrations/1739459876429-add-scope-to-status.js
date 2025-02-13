import { logApp } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Status add scope migration and default to GLOBAL';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const updateQuery = {
    script: {
      source: "if (!ctx._source.containsKey('scope')) { ctx._source.scope = 'GLOBAL' }",
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'Status' } } },
        ],
      },
    },
  };
  await elUpdateByQueryForMigration(
    '[MIGRATION] Status add scope migration and default to GLOBAL',
    [READ_INDEX_INTERNAL_OBJECTS],
    updateQuery
  );
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
