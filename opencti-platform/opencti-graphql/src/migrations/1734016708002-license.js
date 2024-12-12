import { logApp } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Licensing model migration';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const updateQuery = {
    script: {
      source: "if (ctx._source.containsKey('enterprise_edition')) { ctx._source.enterprise_license = ctx._source.enterprise_edition; ctx._source.remove('enterprise_edition'); }",
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'Settings' } } },
        ],
      },
    },
  };
  await elUpdateByQueryForMigration(
    '[MIGRATION] Licensing model migration',
    [READ_INDEX_INTERNAL_OBJECTS],
    updateQuery
  );
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
