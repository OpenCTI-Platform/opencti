import { addCapability } from '../domain/grant';
import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] add the new PIR capabilities';

export const up = async (next) => {
  const context = executionContext('migration');

  await addCapability(context, SYSTEM_USER, {
    name: 'PIRAPI',
    description: 'Access PIR',
    attribute_order: 2900,
  });

  await addCapability(context, SYSTEM_USER, {
    name: 'PIRAPI_PIRUPDATE',
    description: 'Create / Update / Delete PIR',
    attribute_order: 2950,
  });

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
