import { logger } from '../config/conf';
import { executeRead } from '../database/grakn';

module.exports.up = async next => {
  logger.info('[MIGRATION] reindex_elasticsearch_lowercase > Nothing to reindex');
  await executeRead(rTx => {
    rTx.tx.query(`match $x isa Settings;`);
  });
  logger.info(`[MIGRATION] reindex > Migration complete`);
  next();
};

module.exports.down = async next => {
  next();
};
