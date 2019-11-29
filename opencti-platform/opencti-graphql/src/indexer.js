import moment from 'moment';
import { index } from './database/indexing';

const start = moment();
console.log(`> ---------------------------------------------------------------------`);
index().then(() => {
  const execDuration = moment.duration(moment().diff(start));
  console.log(`Indexing done in ${execDuration.asSeconds()} seconds (${execDuration.humanize()})`);
});
