import { elUpdateByQueryForMigration } from '../database/engine';
import { DatabaseError } from '../config/errors';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { logApp } from '../config/conf';

const message = '[MIGRATION] Triggers remove unused fields: recipients, user_ids, group_ids';

const updateTriggers = async () => {
  const updateQuery = {
    script: {
      params: { toRemoveFields: ['user_ids', 'group_ids', 'recipients'] },
      source: 'for(def field : params.toRemoveFields) ctx._source.remove(field)'
    },
    query: {
      bool: {
        must: [
          {
            term: {
              'entity_type.keyword': {
                value: 'trigger'
              }
            }
          }
        ],
        should: [
          {
            exists: {
              field: 'user_ids'
            }
          },
          {
            exists: {
              field: 'group_ids'
            }
          },
          {
            exists: {
              field: 'recipients'
            }
          }
        ],
        minimum_should_match: 1
      }
    }
  };
  return elUpdateByQueryForMigration(message, READ_INDEX_INTERNAL_OBJECTS, updateQuery).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
};
export const up = async (next) => {
  logApp.info(message);
  await updateTriggers();
  next();
};

export const down = async (next) => {
  next();
};
