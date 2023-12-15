import { elUpdateMappingsTemplates } from '../database/engine';

export const up = async (next) => {
  await elUpdateMappingsTemplates();
  next();
};

export const down = async (next) => {
  next();
};
