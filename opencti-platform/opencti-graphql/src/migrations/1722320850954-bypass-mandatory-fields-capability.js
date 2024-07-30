import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';

const message = '[MIGRATION] add the new capability ByPass mandatory fields';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // ------ Create 'Bypass mandatory fields'
  await addCapability(context, SYSTEM_USER, {
    name: 'KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS',
    description: 'Bypass mandatory fields',
    attribute_order: 330
  });

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
