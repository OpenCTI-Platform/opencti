import { logApp } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

const message = '[MIGRATION] update authorized authorities for triggers';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const updateQuery = {
    script: {
      params: { capability: ['SETTINGS_SECURITYACTIVITY'] },
      source: 'ctx._source.authorized_authorities = params.capability',
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'trigger' } } },
          { term: { 'trigger_scope.keyword': { value: 'activity' } } },
        ],
      },
    },
  };
  await elUpdateByQueryForMigration(
    message,
    READ_INDEX_INTERNAL_OBJECTS,
    updateQuery
  );
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
