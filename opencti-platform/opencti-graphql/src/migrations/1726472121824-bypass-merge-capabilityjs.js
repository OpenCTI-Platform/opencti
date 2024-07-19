import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';

const message = '[MIGRATION] add the new capability Bypass merge dependencies access check';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // ------ Create 'Bypass mandatory fields'
  await addCapability(context, SYSTEM_USER, {
    name: 'KNOWLEDGE_KNUPDATE_KNBYPASSRMERGE',
    description: 'Bypass merge dependencies access check',
    attribute_order: 340
  });

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
