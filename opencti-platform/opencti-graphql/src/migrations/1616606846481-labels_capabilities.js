import { createCapabilities, SETTINGS_CAPABILITIES } from '../initialization';

export const up = async (next) => {
  // Create labels capabilities
  await createCapabilities([SETTINGS_CAPABILITIES]);
  next();
};

export const down = async (next) => {
  next();
};
