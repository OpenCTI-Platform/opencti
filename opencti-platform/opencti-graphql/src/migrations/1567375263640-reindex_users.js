import { find, getById } from '../database/grakn';
import { logger } from '../config/conf';

module.exports.up = async next => {
  const query = `match $x isa User; get;`;
  const entities = await find(query, ['x']);
  logger.info('[MIGRATION] reindex_users > Persons loaded');
  await Promise.all(
    entities.map(entity => {
      return getById(entity.x.id, true);
    })
  );
  logger.info('[MIGRATION] reindex_users > Migration complete');
  next();
};

module.exports.down = async next => {
  next();
};
