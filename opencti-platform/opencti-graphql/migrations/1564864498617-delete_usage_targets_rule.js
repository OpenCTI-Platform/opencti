import { write } from '../src/database/grakn';
import { logger } from '../src/config/conf';

module.exports.up = async next => {
  // Delete the default
  try {
    await write('undefine UsageTargetsRule sub rule;')
  } catch(err) {
    logger.info('Undefine the rule (not exists)');
  }
  next();
};

module.exports.down = async next => {
  next();
};