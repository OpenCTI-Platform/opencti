import { logger } from '../config/conf';

module.exports.up = async next => {
  logger.info('[MIGRATION] reindex_elasticsearch_lowercase > Nothing to reindex');
  next();
};

module.exports.down = async next => {
  next();
};
