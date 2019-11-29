import { write } from '../database/grakn';
import { logger } from '../config/conf';

module.exports.up = async next => {
  // Delete the default
  try {
    await write('undefine UsageTargetsRule sub rule;');
  } catch (err) {
    logger.info(
      '[MIGRATION] delete_usage_targets_rule > Undefine the rule (not exists)'
    );
  }
  next();
};

module.exports.down = async next => {
  next();
};
