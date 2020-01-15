import moment from 'moment';
import index from './database/indexing';
import { logger } from './config/conf';

const start = moment();
logger.info(`> ---------------------------------------------------------------------`);
index().then(() => {
  const execDuration = moment.duration(moment().diff(start));
  logger.info(`Indexing done in ${execDuration.asSeconds()} seconds (${execDuration.humanize()})`);
});
