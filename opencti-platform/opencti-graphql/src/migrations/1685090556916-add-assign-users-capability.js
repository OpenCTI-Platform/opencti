import { executionContext, SYSTEM_USER } from '../utils/access';
import { logApp } from '../config/conf';
import { addCapability } from '../domain/grant';

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info('[MIGRATION] Starting Add assign users capability migration');
  await addCapability(context, SYSTEM_USER, {
    name: 'KNOWLEDGE_KNUPDATE_KNASSIGN',
    description: 'Assign users',
    attribute_order: 250
  });
  logApp.info('[MIGRATION] Add assign users capability done.');
  next();
};

export const down = async (next) => {
  next();
};
