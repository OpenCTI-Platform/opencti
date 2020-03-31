import { logger } from '../config/conf';
import { executeRead } from '../database/grakn';

export const up = async (next) => {
  logger.info('[MIGRATION] reindex_users > Nothing to reindex');
  await executeRead((rTx) => {
    rTx.tx.query(`match $x isa Settings;`);
  });
  next();
};

export const down = async (next) => {
  next();
};
