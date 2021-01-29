import { head } from 'ramda';
import * as R from 'ramda';
import { elPaginate } from '../database/elasticSearch';
import conf from '../config/conf';
import { EVENT_TYPE_CREATE } from '../database/rabbitmq';
import { findById, SYSTEM_USER } from './user';
import { ABSTRACT_STIX_CORE_OBJECT } from '../schema/general';
import { loadById, timeSeriesEntities } from '../database/middleware';
import { READ_INDEX_HISTORY } from '../database/utils';

export const findAll = (user, args) => {
  const finalArgs = R.pipe(
    R.assoc('type', ['history']),
    R.assoc('orderBy', args.orderBy || 'timestamp'),
    R.assoc('orderMode', args.orderMode || 'desc')
  )(args);
  return elPaginate(user, READ_INDEX_HISTORY, finalArgs);
};

export const creator = async (user, entityId) => {
  const entity = await loadById(user, entityId, ABSTRACT_STIX_CORE_OBJECT);
  return elPaginate(user, READ_INDEX_HISTORY, {
    orderBy: 'timestamp',
    orderMode: 'asc',
    filters: [
      { key: 'event_type', values: [EVENT_TYPE_CREATE] },
      { key: 'context_data.id', values: [entity.internal_id] },
    ],
    connectionFormat: false,
  }).then(async (logs) => {
    const applicant = logs.length > 0 ? head(logs).applicant_id || head(logs).user_id : null;
    const finalUser = applicant ? await findById(user, applicant) : undefined;
    return finalUser || SYSTEM_USER;
  });
};

export const logsTimeSeries = (user, args) => {
  let filters = [];
  if (args.userId) {
    filters = [{ isRelation: false, type: '*_id', value: args.userId }];
  }
  return timeSeriesEntities(user, null, filters, args);
};

export const logsWorkerConfig = () => ({
  elasticsearch_url: conf.get('elasticsearch:url'),
  elasticsearch_index: READ_INDEX_HISTORY,
});
