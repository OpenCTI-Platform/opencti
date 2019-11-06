import { reindexByQuery } from '../database/grakn';
import { logger } from '../config/conf';

module.exports.up = async next => {
  const query = `match $x isa User; get;`;
  const count = await reindexByQuery(query, ['x']);
  logger.info(
    `[MIGRATION] reindex_users > Migration complete, ${count} persons loaded`
  );
  next();
};

module.exports.down = async next => {
  next();
};
