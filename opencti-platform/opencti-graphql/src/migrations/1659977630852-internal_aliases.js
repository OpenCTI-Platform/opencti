import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';
import { DatabaseError } from '../config/errors';

export const up = async (next) => {
  const updateQuery = {
    script: {
      source: 'ctx._source.i_aliases_ids = ctx._source.i_aliases_ids.stream().distinct().collect(Collectors.toList())',
    },
    query: {
      bool: {
        must: [{ exists: { field: 'i_aliases_ids' } }],
      },
    },
  };
  await elUpdateByQueryForMigration('[MIGRATION] Rewriting aliases', READ_DATA_INDICES, updateQuery)
    .catch((err) => {
      throw DatabaseError('Error updating elastic', { error: err });
    });
  next();
};

export const down = async (next) => {
  next();
};
