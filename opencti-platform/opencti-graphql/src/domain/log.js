import { head } from 'ramda';
import * as R from 'ramda';
import { elPaginate } from '../database/engine';
import conf, { booleanConf } from '../config/conf';
import { EVENT_TYPE_CREATE } from '../database/rabbitmq';
import { findById } from './user';
import { storeLoadById, timeSeriesEntities } from '../database/middleware';
import { READ_INDEX_HISTORY, INDEX_HISTORY } from '../database/utils';
import { SYSTEM_USER } from '../utils/access';

export const findAll = (user, args) => {
  const finalArgs = R.pipe(
    R.assoc('types', ['history']),
    R.assoc('orderBy', args.orderBy || 'timestamp'),
    R.assoc('orderMode', args.orderMode || 'desc')
  )(args);
  return elPaginate(user, READ_INDEX_HISTORY, finalArgs);
};

export const creator = async (user, entityId, type) => {
  const entity = await storeLoadById(user, entityId, type);
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

export const logsWorkerConfig = () => {
  const elasticSearchUrl = conf.get('elasticsearch:url');
  return {
    elasticsearch_url: Array.isArray(elasticSearchUrl) ? elasticSearchUrl : [elasticSearchUrl],
    elasticsearch_proxy: conf.get('elasticsearch:proxy') || null,
    elasticsearch_index: INDEX_HISTORY,
    elasticsearch_username: conf.get('elasticsearch:username') || null,
    elasticsearch_password: conf.get('elasticsearch:password') || null,
    elasticsearch_api_key: conf.get('elasticsearch:api_key') || null,
    elasticsearch_ssl_reject_unauthorized: booleanConf('elasticsearch:ssl:reject_unauthorized', true),
  };
};
