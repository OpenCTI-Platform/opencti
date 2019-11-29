import { logger } from '../config/conf';

module.exports.up = async next => {
  logger.info('[MIGRATION] reindex_elasticsearch_lowercase > Nothing to elReindex');
  next();
};

module.exports.down = async next => {
  next();
};
