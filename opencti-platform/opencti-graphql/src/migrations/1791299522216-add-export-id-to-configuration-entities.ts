import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_META_OBJECTS } from '../database/utils';
import { exportIdOnCreationQuery } from '../schema/export-id';

const message = '[MIGRATION] Add export_id to configuration entities';

// Runs after the built-in export_id migration: built-in elements keep their deterministic export_id,
// the other configuration elements get their internal_id, as they do when created.
export const up = async (next: (error?: Error) => void) => {
  logMigration.info(`${message} > started`);
  const updateQuery = {
    script: {
      source: 'ctx._source.export_id = ctx._source.internal_id;',
    },
    query: {
      bool: {
        must: [exportIdOnCreationQuery()],
        must_not: [{ exists: { field: 'export_id' } }],
      },
    },
  };
  await elUpdateByQueryForMigration(message, [READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_META_OBJECTS].join(','), updateQuery);
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
