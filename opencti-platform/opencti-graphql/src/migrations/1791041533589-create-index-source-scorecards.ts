import { logMigration } from '../config/conf';
import { elCreateIndex } from '../database/engine';
import { INDEX_SOURCE_SCORECARDS } from '../database/utils';

const message = '[MIGRATION] Source intelligence scorecards index';

// The index is idempotently created; sources, scorecards and the historical snapshots (backfill) are then computed by
// the source intelligence manager in bounded steps, so the platform startup is not blocked by the computation.
export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  await elCreateIndex(INDEX_SOURCE_SCORECARDS);
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
