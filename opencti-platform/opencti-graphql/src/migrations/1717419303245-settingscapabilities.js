import { logApp } from '../config/conf';
import { elLoadById, elReplace } from '../database/engine';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] update settings capabilities';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // ------ Update description of Access Administration
  const adminCapability = await elLoadById(context, SYSTEM_USER, 'capability--bb5ec6d0-0ffb-5b04-8fcf-c0d4447209a6');
  const adminCapabilityPatch = { description: 'Access to admin functionalities' };
  await elReplace(adminCapability._index, adminCapability.internal_id, { doc: adminCapabilityPatch });

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
