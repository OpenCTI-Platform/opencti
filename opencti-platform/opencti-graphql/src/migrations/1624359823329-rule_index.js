import { elCreateIndexes } from '../database/engine';
import { INDEX_INFERRED_ENTITIES, INDEX_INFERRED_RELATIONSHIPS } from '../database/utils';

export const up = async (next) => {
  await elCreateIndexes([INDEX_INFERRED_ENTITIES, INDEX_INFERRED_RELATIONSHIPS]);
  next();
};

export const down = async (next) => {
  next();
};
