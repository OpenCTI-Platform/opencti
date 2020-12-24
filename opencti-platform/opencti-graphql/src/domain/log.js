import { head, assoc } from 'ramda';
import { elPaginate, INDEX_HISTORY } from '../database/elasticSearch';
import conf from '../config/conf';
import { EVENT_TYPE_CREATE } from '../database/rabbitmq';
import { findById, SYSTEM_USER } from './user';
import { ABSTRACT_STIX_CORE_OBJECT } from '../schema/general';
import { loadById, timeSeriesEntities } from '../database/middleware';

export const findAll = (args) => elPaginate(INDEX_HISTORY, assoc('types', ['history'], args));

export const creator = async (entityId) => {
  const entity = await loadById(entityId, ABSTRACT_STIX_CORE_OBJECT);
  return elPaginate(INDEX_HISTORY, {
    filters: [
      { key: 'event_type', values: [EVENT_TYPE_CREATE] },
      { key: 'context_data.id', values: [entity.internal_id] },
    ],
    connectionFormat: false,
  }).then(async (logs) => {
    const user = logs.length > 0 ? head(logs).applicant_id || head(logs).user_id : null;
    let finalUser = null;
    if (user) {
      finalUser = await findById(user);
    }
    return finalUser || SYSTEM_USER;
  });
};

export const logsTimeSeries = (args) => {
  let filters = [];
  if (args.userId) {
    filters = [{ isRelation: false, type: '*_id', value: args.userId }];
  }
  return timeSeriesEntities(null, filters, args);
};

export const logsWorkerConfig = () => ({
  elasticsearch_url: conf.get('elasticsearch:url'),
  elasticsearch_index: INDEX_HISTORY,
});
