import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';

const message = '[MIGRATION] add the new dissemination capabilities';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // ------ Create 'Manage disseminationlists'
  await addCapability(context, SYSTEM_USER, {
    name: 'SETTINGS_SETDISSEMINATION',
    description: 'Manage dissemination lists',
    attribute_order: 3320
  });

  // ------ Create 'Disseminate files'
  await addCapability(context, SYSTEM_USER, {
    name: 'KNOWLEDGE_KNDISSEMINATION',
    description: 'Disseminate files by email',
    attribute_order: 900
  });

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
