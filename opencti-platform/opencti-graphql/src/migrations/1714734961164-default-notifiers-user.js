import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { STATIC_NOTIFIER_EMAIL, STATIC_NOTIFIER_UI } from '../modules/notifier/notifier-statics';

const message = '[MIGRATION] Add default triggers for assignation and participation to users';
export const up = async (next) => {
  const updateQuery = {
    script: {
      params: { notifiers: [STATIC_NOTIFIER_UI, STATIC_NOTIFIER_EMAIL] },
      source: 'ctx._source.personal_notifiers = params.notifiers',
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'User' } } },
        ],
        must_not: [
          { exists: { field: 'personal_notifiers' } }
        ]
      },
    },
  };
  await elUpdateByQueryForMigration(
    message,
    [READ_INDEX_INTERNAL_OBJECTS],
    updateQuery
  );
  next();
};

export const down = async (next) => {
  next();
};
