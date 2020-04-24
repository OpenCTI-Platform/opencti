import { elPaginate, INDEX_LOGS } from '../database/elasticSearch';
import conf from '../config/conf';

export const findAll = async (args) => {
  const filters = [];
  if (args.type) {
    filters.push({ key: 'event_type', values: [args.type] });
  }
  if (args.entityId) {
    filters.push({ key: 'entity_id', values: [args.entityId] });
  }
  return elPaginate(INDEX_LOGS, {
    orderBy: args.orderBy || 'created_at',
    orderMode: args.orderMode || 'asc',
    filters,
  });
};

export const logsWorkerConfig = () => ({
  elasticsearch_url: conf.get('elasticsearch:url'),
});
