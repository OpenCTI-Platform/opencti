import { logger } from '../config/conf';
import { executeRead } from '../database/grakn';

module.exports.up = async next => {
  logger.info('[MIGRATION] reindex_users > Nothing to reindex');
  await executeRead(rTx => {
    rTx.tx.query(`match $x isa Settings;`);
  });
  next();
};

module.exports.down = async next => {
  next();
};
