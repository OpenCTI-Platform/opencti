import { elUpdateByQueryForMigration, elUpdateIndicesMappings } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';

export const up = async (next) => {
  await elUpdateIndicesMappings({
    user_confidence_level: {
      dynamic: 'strict',
      properties: {
        max_confidence: {
          coerce: false,
          type: 'integer'
        },
        overrides: {
          dynamic: 'strict',
          type: 'nested',
          properties: {
            max_confidence: {
              coerce: false,
              type: 'integer'
            },
            entity_type: {
              type: 'text',
              fields: {
                keyword: {
                  normalizer: 'string_normalizer',
                  ignore_above: 512,
                  type: 'keyword'
                }
              }
            }
          }
        }
      }
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
