import { filter, map, assoc } from 'ramda';
import moment from 'moment';
import { statsQueues } from '../database/rabbitmq';

const dateFormat = 'YYYY-MM-DDTHH:mm:ss';

export const getMetrics = async args => {
  const queues = await statsQueues();
  const finalQueues = map(
    n => assoc('idle_since', `${moment(n.idle_since).format(dateFormat)}Z`, n),
    queues
  );

  if (args.prefix) {
    return filter(n => n.name.includes(args.prefix), finalQueues);
  }
  return finalQueues;
};
