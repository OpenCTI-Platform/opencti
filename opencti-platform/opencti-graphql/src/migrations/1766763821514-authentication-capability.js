import { addCapability } from '../domain/grant';
import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] add the new SETAUTH capability';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  await addCapability(context, SYSTEM_USER, {
    name: 'SETTINGS_SETAUTH',
    description: 'Manage authentication',
    attribute_order: 3220,
  });

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
