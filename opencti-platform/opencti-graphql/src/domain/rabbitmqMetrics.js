import { filter, map, assoc } from 'ramda';
import { parseISO } from 'date-fns';
import { metrics } from '../database/rabbitmq';

export const getMetrics = async (context, user, args) => {
  const stats = await metrics(context, user);
  const finalQueues = map((n) => assoc('idle_since', new Date(n.idle_since).toISOString(), n), stats.queues);
  if (args.prefix) {
    return assoc('queues', filter((n) => n.name.includes(args.prefix), finalQueues), stats);
  }
  return assoc('queues', finalQueues, stats);
};
