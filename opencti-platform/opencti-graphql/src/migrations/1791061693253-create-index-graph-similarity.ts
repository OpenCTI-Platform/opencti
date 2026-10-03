import { logMigration } from '../config/conf';
import { elCreateIndex, elIndexExists } from '../database/engine';
import { INDEX_GRAPH_SIMILARITY } from '../database/utils';

const message = '[MIGRATION] Create graph analytics similarity index';

// Only the index is created here: the similarity and graph metrics backfill is done by the
// graph analytics manager on its first full pass, outside of the blocking migration process.
export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const alreadyExists = await elIndexExists(INDEX_GRAPH_SIMILARITY);
  if (!alreadyExists) {
    await elCreateIndex(INDEX_GRAPH_SIMILARITY);
  }
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
