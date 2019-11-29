import { createIndexes, reindex } from '../database/elasticSearch';
import { logger } from '../config/conf';

module.exports.up = async next => {
  try {
    // create new indexes
    await createIndexes();
  } catch (err) {
    logger.info(
      '[MIGRATION] reindex_elasticsearch_lowercase > Index already exists'
    );
  }
  try {
    // Reindex
    await reindex([
      { source: 'stix-domain-entities', dest: 'stix_domain_entities' },
      { source: 'stix-relations', dest: 'stix_relations' },
      { source: 'stix-observables', dest: 'stix_observables' },
      { source: 'external-references', dest: 'external_references' }
    ]);
    logger.info(
      '[MIGRATION] reindex_elasticsearch_lowercase > Migration reindex'
    );
  } catch (err) {
    logger.info(
      '[MIGRATION] reindex_elasticsearch_lowercase > Nothing to reindex'
    );
  }
  next();
};

module.exports.down = async next => {
  next();
};
