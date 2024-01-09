import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

export const up = async (next) => {
  const updateQuery = {
    script: {
      source: "if (!ctx._source.containsKey('platform_messages')) { ctx._source.platform_messages = ctx._source.messages; ctx._source.remove('messages'); }",
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
    '[MIGRATION] Renaming platform messages attribute',
    [READ_INDEX_INTERNAL_OBJECTS],
    updateQuery
  );
  next();
};

export const down = async (next) => {
  next();
};
