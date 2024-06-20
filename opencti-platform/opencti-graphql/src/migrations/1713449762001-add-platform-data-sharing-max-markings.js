// import { executionContext, SYSTEM_USER } from '../utils/access';
// import { getSettings, settingsEditField } from '../domain/settings';
// import { logApp } from '../config/conf';

export const up = async (next) => {
  // ----- Explanations ----------
  // This migration has been removed
  // because platform_data_sharing_max_markings does not exist anymore since version 6.1.11
  // -----------------------------

  // -------- Old code -----------
  // logApp.info('[MIGRATION] Add platform data sharing max markings');
  // const context = executionContext('migration');
  // ------ Add platform_data_sharing_max_markings
  // const settings = await getSettings(context);
  // const patch = [{ key: 'platform_data_sharing_max_markings', value: [] }];
  // await settingsEditField(context, SYSTEM_USER, settings.id, patch);
  // logApp.info('[MIGRATION] Add platform data sharing max markings done.');
  next();
};

export const down = async (next) => {
  next();
};
