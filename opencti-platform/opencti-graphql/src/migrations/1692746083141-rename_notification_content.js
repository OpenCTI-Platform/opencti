import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

export const up = async (next) => {
  const query = {
    script: {
      params: { content: 'content' },
      source: 'ctx._source.notification_content = ctx._source.content; ctx._source.remove(params.content) ',
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'Notification' } } },
        ],
      },
    },
  };
  await elUpdateByQueryForMigration('[MIGRATION] Rename notification attribute content', READ_INDEX_INTERNAL_OBJECTS, query);
  next();
};

export const down = async (next) => {
  next();
};
