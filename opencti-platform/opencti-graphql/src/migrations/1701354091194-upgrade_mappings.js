import { elUpdateIndicesMappings } from '../database/engine';

export const up = async (next) => {
  await elUpdateIndicesMappings(); // Update without params to only reset the templates
  next();
};

export const down = async (next) => {
  next();
};
