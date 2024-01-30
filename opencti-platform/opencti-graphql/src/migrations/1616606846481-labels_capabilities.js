import { createCapabilities, SETTINGS_CAPABILITIES } from '../database/data-initialization';
import { executionContext } from '../utils/access';

export const up = async (next) => {
  const context = executionContext('migration');
  // Create labels capabilities
  await createCapabilities(context, [SETTINGS_CAPABILITIES]);
  next();
};

export const down = async (next) => {
  next();
};
