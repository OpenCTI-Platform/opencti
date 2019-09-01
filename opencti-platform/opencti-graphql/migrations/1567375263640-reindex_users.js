import { find, getById } from '../src/database/grakn';
import { logger } from '../src/config/conf';

module.exports.up = async next => {
  const query = `match $x isa User; get $x;`;
  const entities = await find(query, ['x']);
  logger.info('Persons loaded');
  await Promise.all(
    entities.map(entity => {
      return getById(entity.x.id, true);
    })
  );
  logger.info('Migration complete');
  next();
};

module.exports.down = async next => {
  next();
};
