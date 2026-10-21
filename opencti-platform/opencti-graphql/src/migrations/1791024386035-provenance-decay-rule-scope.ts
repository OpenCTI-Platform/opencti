import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_DECAY_RULE } from '../modules/decayRule/decayRule-types';

const message = '[MIGRATION] Scope the existing decay rules to indicators';

/**
 * Decay rules now target indicators, relationships or entities (knowledge decay).
 * Every existing rule is an indicator decay rule. Provenance attributes mappings are created at startup,
 * the provenance of the existing knowledge is rebuilt in the background by the provenance backfill manager.
 */
export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const updateQuery = {
    script: {
      source: "ctx._source.target_scope = 'indicator';",
      lang: 'painless',
    },
    query: {
      bool: {
        must: [{ term: { 'entity_type.keyword': ENTITY_TYPE_DECAY_RULE } }],
        must_not: [{ exists: { field: 'target_scope' } }],
      },
    },
  };
  await elUpdateByQueryForMigration(message, READ_INDEX_INTERNAL_OBJECTS, updateQuery);
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
