import { logApp } from '../config/conf';
import { searchClient } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';
import { DatabaseError } from '../config/errors';

export const up = async (next) => {
  logApp.info('[MIGRATION] Rewriting aliases to ensure uniqueness');
  await searchClient()
    .updateByQuery({ index: READ_DATA_INDICES,
      refresh: true,
      body: {
        script: {
          source: 'ctx._source.i_aliases_ids = ctx._source.i_aliases_ids.stream().distinct().collect(Collectors.toList())',
        },
        query: {
          bool: {
            must: [{ exists: { field: 'i_aliases_ids' } }],
          },
        },
      } })
    .catch((err) => {
      throw DatabaseError('Error updating elastic', { error: err });
    });
  next();
};

export const down = async (next) => {
  next();
};
