import { logMigration } from '../config/conf';
import { elLoadById, elReplace } from '../database/engine';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] migration title';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  // ------ Update description of SETTINGS_SETPARAMETERS
  const setParametersCapability = await elLoadById(context, SYSTEM_USER, 'capability--d6dd23a1-4f95-58f1-aa06-a9ed4e3ff33b');
  const setParametersCapabilityPatch = { description: 'Manage parameters' };
  await elReplace(setParametersCapability._index, setParametersCapability.internal_id, { doc: setParametersCapabilityPatch });
  // ------ Update description of SETTINGS_SUPPORT
  const setSupportCapability = await elLoadById(context, SYSTEM_USER, 'capability--b91b5483-5d6d-59a2-9ee1-a39ca7ebaab7');
  const setSupportCapabilityPatch = { description: 'Access to support data' };
  await elReplace(setSupportCapability._index, setSupportCapability.internal_id, { doc: setSupportCapabilityPatch });

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
