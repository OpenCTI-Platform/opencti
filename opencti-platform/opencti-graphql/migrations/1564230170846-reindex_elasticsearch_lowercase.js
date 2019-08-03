import {
  createIndexes,
  deleteIndexes,
  reindex
} from '../src/database/elasticSearch';
import { logger } from '../src/config/conf';

module.exports.up = async next => {
  // Delete the default
  try {
    await deleteIndexes();
    // create new indexes
    await createIndexes();
    // Reindex
    await reindex([
      { source: 'stix-domain-entities', dest: 'stix_domain_entities' },
      { source: 'stix-relations', dest: 'stix_relations' },
      { source: 'stix-observables', dest: 'stix_observables' },
      { source: 'external-references', dest: 'external_references' }
    ]);
  }
  catch(err) {
      logger.info('Not deleting indexes (not exists)');
    }
  next();
};

module.exports.down = async next => {
  next();
};