import { executionContext, SYSTEM_USER } from '../utils/access';
import { getSettings, settingsEditField } from '../domain/settings';
import { logApp } from '../config/conf';

export const up = async (next) => {
  logApp.info('[MIGRATION] Add platform data sharing max markings');
  const context = executionContext('migration');
  // ------ Add platform_data_sharing_max_markings
  const settings = await getSettings(context);
  const patch = [{ key: 'platform_data_sharing_max_markings', value: [] }];
  await settingsEditField(context, SYSTEM_USER, settings.id, patch);
  logApp.info('[MIGRATION] Add platform data sharing max markings done.');
  next();
};

export const down = async (next) => {
  next();
};
