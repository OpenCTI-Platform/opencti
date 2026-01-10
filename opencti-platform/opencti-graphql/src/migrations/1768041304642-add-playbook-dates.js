import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';

const message = '[MIGRATION] Add created_at and updated_at to existing playbooks';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  
  // Add created_at and updated_at fields to playbooks that don't have them
  const now = new Date().getTime();
  const updateQuery = {
    script: {
      params: { now },
      source: `
        if (ctx._source.entity_type == 'Playbook') {
          if (ctx._source.created_at == null) {
            ctx._source.created_at = params.now;
          }
          if (ctx._source.updated_at == null) {
            ctx._source.updated_at = params.now;
          }
        }
      `,
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': 'Playbook' } },
        ],
        should: [
          { bool: { must_not: { exists: { field: 'created_at' } } } },
          { bool: { must_not: { exists: { field: 'updated_at' } } } },
        ],
        minimum_should_match: 1,
      },
    },
  };
  
  await elUpdateByQueryForMigration(
    message,
    READ_DATA_INDICES,
    updateQuery,
  );
  
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
