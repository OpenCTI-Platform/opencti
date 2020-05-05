import { filter, map, assoc } from 'ramda';
import moment from 'moment';
import { metrics } from '../database/rabbitmq';

// eslint-disable-next-line
export const getMetrics = async (args) => {
  const stats = await metrics();
  const finalQueues = map(
    (n) => assoc('idle_since', moment(n.idle_since, 'YYYY-MM-DD hh:mm:ss').toISOString(), n),
    stats.queues
  );
  if (args.prefix) {
    return assoc(
      'queues',
      filter((n) => n.name.includes(args.prefix), finalQueues),
      stats
    );
  }
  return assoc('queues', finalQueues, stats);
};
