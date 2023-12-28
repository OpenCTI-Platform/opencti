import { elUpdateByQueryForMigration, elUpdateIndicesMappings } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';

export const up = async (next) => {
  await elUpdateIndicesMappings({
    user_confidence_level: {
      properties: {
        max_confidence: { type: 'integer' },
        overrides: {
          type: 'nested',
          properties: {
            entity_type: { type: 'keyword' },
            max_confidence: { type: 'integer' },
          },
        }
      },
    },
  });

  // set all user's confidence level to 100, no override
  const updateQuery = {
    script: {
      params: {
        user_confidence_level: {
          max_confidence: 100,
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
    '[MIGRATION] Adding default user confidence = 100',
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
