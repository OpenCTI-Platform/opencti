import { logger } from '../config/conf';
import { executeRead } from '../database/grakn';

export const up = async (next) => {
  logger.info('[MIGRATION] reindex_elasticsearch_lowercase > Nothing to reindex');
  await executeRead((rTx) => {
    rTx.tx.query(`match $x isa Settings;`);
  });
  logger.info(`[MIGRATION] reindex > Migration complete`);
  next();
};

export const down = async (next) => {
  next();
};
