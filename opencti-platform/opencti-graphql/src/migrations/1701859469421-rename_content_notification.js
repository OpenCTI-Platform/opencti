import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

export const up = async (next) => {
  const updateQuery = {
    script: {
      source: "if (!ctx._source.containsKey('notification_content')) { ctx._source.notification_content = ctx._source.content; ctx._source.remove('content'); }",
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'Notification' } } },
        ],
      },
    },
  };
  await elUpdateByQueryForMigration(
    '[MIGRATION] Renaming content attribute',
    [READ_INDEX_INTERNAL_OBJECTS],
    updateQuery
  );
  next();
};

export const down = async (next) => {
  next();
};
