import { write } from '../database/grakn';
import { logger } from '../config/conf';

export const up = async next => {
  // Delete the default
  try {
    await write('undefine UserTargetsRule sub rule;');
  } catch (err) {
    logger.info('[MIGRATION] delete_user_targets_rule > Undefine the rule (not exists)');
  }
  next();
};

export const down = async next => {
  next();
};
