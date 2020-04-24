import { head } from 'ramda';
import { elPaginate, INDEX_LOGS } from '../database/elasticSearch';
import conf from '../config/conf';
import { amqpUri } from '../database/rabbitmq';
import { EVENT_TYPE_CREATE } from '../database/utils';

export const findAll = async (args) => {
  const filters = [];
  if (args.type) {
    filters.push({ key: 'event_type', values: [args.type] });
  }
  if (args.entityId) {
    filters.push({ key: 'event_entity_id', values: [args.entityId] });
  }
  return elPaginate(INDEX_LOGS, {
    orderBy: args.orderBy || 'created_at',
    orderMode: args.orderMode || 'asc',
    filters,
  });
};

export const creator = async (entityId) => {
  return elPaginate(INDEX_LOGS, {
    filters: [
      { key: 'event_type', values: [EVENT_TYPE_CREATE] },
      { key: 'event_entity_id', values: [entityId] },
    ],
    connectionFormat: false,
  }).then((logs) => (logs.length > 0 ? head(logs).event_user : null));
};

export const logsWorkerConfig = () => ({
  elasticsearch_url: conf.get('elasticsearch:url'),
  elasticsearch_index: INDEX_LOGS,
  rabbitmq_url: amqpUri(),
});
