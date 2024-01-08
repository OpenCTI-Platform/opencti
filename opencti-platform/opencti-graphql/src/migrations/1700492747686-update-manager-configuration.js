import { findByManagerId, managerConfigurationResetSetting } from '../modules/managerConfiguration/managerConfiguration-domain';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { logApp } from '../config/conf';

const message = '[MIGRATION] update manager configuration';
export const up = async (next) => {
  logApp.info(`${message} > started`);
  // update mapping for new field manager_setting that needs to be a flattened type
  const context = executionContext('migration', SYSTEM_USER);
  const managerConfigurationToUpdate = await findByManagerId(context, context.user, 'FILE_INDEX_MANAGER');
  if (managerConfigurationToUpdate) {
    // reset managerConfiguration
    await managerConfigurationResetSetting(context, context.user, managerConfigurationToUpdate.id);
  }
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
