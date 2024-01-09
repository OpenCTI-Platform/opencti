import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';

export const up = async (next) => {
  // set all user's confidence level to 0, no override
  // the goal of this migration is to give users some times to set properly their confidence levels
  // without them being used yet.
  const updateQuery = {
    script: {
      params: {
        user_confidence_level: {
          max_confidence: 0,
          overrides: [],
        },
      },
      source: 'ctx._source.user_confidence_level = params.user_confidence_level;',
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'User' } } },
        ],
      },
    },
  };

  await elUpdateByQueryForMigration(
    '[MIGRATION] Adding default user confidence = 0',
    READ_INDEX_INTERNAL_OBJECTS,
    updateQuery,
  ).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });

  next();
};

export const down = async (next) => {
  next();
};
