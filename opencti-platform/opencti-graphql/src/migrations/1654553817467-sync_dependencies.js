import { searchClient } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';

export const up = async (next) => {
  await searchClient()
    .updateByQuery({ index: READ_INDEX_INTERNAL_OBJECTS,
      refresh: true,
      body: {
        script: {
          params: { no_dependencies: false },
          source: 'ctx._source.no_dependencies = params.no_dependencies;',
        },
        query: {
          bool: {
            must: [
              { term: { 'entity_type.keyword': { value: 'Sync' } } },
            ],
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
