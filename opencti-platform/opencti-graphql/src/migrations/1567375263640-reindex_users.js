import { logger } from '../config/conf';

module.exports.up = async next => {
  logger.info('[MIGRATION] reindex_users > Nothing to reindex');
  next();
};

module.exports.down = async next => {
  next();
};
