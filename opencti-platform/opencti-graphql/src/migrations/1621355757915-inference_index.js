import { elCreateIndexes } from '../database/elasticSearch';
import { INDEX_STIX_CORE_RELATIONSHIPS_INFERRED } from '../database/utils';

export const up = async (next) => {
  await elCreateIndexes([INDEX_STIX_CORE_RELATIONSHIPS_INFERRED]);
  next();
};

export const down = async (next) => {
  next();
};
