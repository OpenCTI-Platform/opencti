import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_HUNT } from '../modules/hunt/hunt-types';

const message = '[MIGRATION] Stop the automatic escalation of the manual runs of the existing hunts';

/**
 * Runs started by hand no longer open an incident draft by themselves above the escalation threshold: it becomes the
 * per-hunt option escalate_manual_runs, off by default, and the incident is offered when a true positive verdict is set.
 * Scheduled, standing, PIR, playbook and emulation runs keep escalating automatically.
 */
export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const updateQuery = {
    script: {
      source: 'ctx._source.escalate_manual_runs = false;',
      lang: 'painless',
    },
    query: {
      bool: {
        must: [{ term: { 'entity_type.keyword': ENTITY_TYPE_HUNT } }],
        must_not: [{ exists: { field: 'escalate_manual_runs' } }],
      },
    },
  };
  await elUpdateByQueryForMigration(message, READ_INDEX_STIX_DOMAIN_OBJECTS, updateQuery);
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
