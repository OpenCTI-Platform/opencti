import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';
import { logApp } from '../config/conf';

export const up = async (next) => {
  logApp.info('[MIGRATION] Starting 1651939301056-workflow_rename.js');
  const updateQuery = {
    script: {
      params: { from: 'status_id', to: 'x_opencti_workflow_id' },
      source: 'ctx._source[params.to] = ctx._source.remove(params.from);',
    },
    query: {
      bool: {
        must: [{ exists: { field: 'status_id' } }],
      },
    },
  };
  await elUpdateByQueryForMigration(
    '[MIGRATION] Migrating workflow status',
    READ_DATA_INDICES,
    updateQuery
  );
  next();
};

export const down = async (next) => {
  next();
};
