import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Setting default platform theme to "Dark"';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const updateQuery = {
    query: {
      match: {
        'entity_type.keyword': 'Settings'
      }
    },
    script: {
      source: "ctx._source.platform_theme = 'Dark'",
      lang: 'painless'
    }
  };
  await elUpdateByQueryForMigration(
    message,
    [READ_INDEX_INTERNAL_OBJECTS],
    updateQuery
  );
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
