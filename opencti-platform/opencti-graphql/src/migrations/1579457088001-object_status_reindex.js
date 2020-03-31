import { elDeleteIndexes, elIndexExists, elReindex } from '../database/elasticSearch';
import { INDEX_STIX_ENTITIES } from '../database/utils';

export const up = async (next) => {
  const applyMigration = await elIndexExists('stix_domain_entities');
  if (applyMigration) {
    await elReindex([{ source: 'stix_domain_entities', dest: INDEX_STIX_ENTITIES }]);
    await elDeleteIndexes(['stix_domain_entities']);
  }
  next();
};

export const down = async (next) => {
  // Reverting this cannot be done because we define the schema directly with the code...
  next();
};
