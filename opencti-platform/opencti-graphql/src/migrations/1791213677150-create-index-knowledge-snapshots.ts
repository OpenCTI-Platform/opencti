import { logMigration } from '../config/conf';
import { elCreateIndex } from '../database/engine';
import { INDEX_KNOWLEDGE_SNAPSHOTS } from '../database/utils';

const message = '[MIGRATION] Create index knowledge snapshots';

// Knowledge snapshots (time machine) are stored in a dedicated index.
// The creation is idempotent: nothing is done if the index already exists.
// No backfill is needed: the snapshot manager starts its history cursor one snapshot period back
// and the time machine replays the existing history from the current documents.
export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  await elCreateIndex(INDEX_KNOWLEDGE_SNAPSHOTS);
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
