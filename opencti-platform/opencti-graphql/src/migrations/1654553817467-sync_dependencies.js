import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

export const up = async (next) => {
  const updateQuery = {
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
  };
  await elUpdateByQueryForMigration(
    '[MIGRATION] Migrating synchronizers',
    READ_INDEX_INTERNAL_OBJECTS,
    updateQuery
  );
  next();
};

export const down = async (next) => {
  next();
};
