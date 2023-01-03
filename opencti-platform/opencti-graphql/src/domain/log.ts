import { elPaginate } from '../database/engine';
import conf, { booleanConf } from '../config/conf';
import { timeSeriesEntities } from '../database/middleware';
import { EVENT_TYPE_CREATE, INDEX_HISTORY, READ_INDEX_HISTORY } from '../database/utils';
import { OPENCTI_SYSTEM_UUID } from '../schema/general';
import { ENTITY_TYPE_HISTORY } from '../schema/internalObject';
import type { CreateEntity, DomainFindAll } from './domainTypes';
import type { AuthContext, AuthUser } from '../types/user';
import type { Log, LogConnection } from '../types/log';

export const findAll: DomainFindAll<LogConnection> = (context, user, args) => {
  const finalArgs = {
    orderBy: 'timestamp',
    orderMode: 'desc',
    ...args,
    types: [ENTITY_TYPE_HISTORY],
  };
  return elPaginate(context, user, READ_INDEX_HISTORY, finalArgs);
};

export const creatorFromHistory: CreateEntity<Log> = async (context, user, entityId) => {
  return elPaginate(context, user, READ_INDEX_HISTORY, {
    size: 1,
    filters: [
      { key: 'event_type', values: [EVENT_TYPE_CREATE] },
      { key: 'context_data.id', values: [entityId] },
    ],
    connectionFormat: false,
  }).then(async (logs: any[]) => {
    const userId = logs.length > 0 ? logs[0].applicant_id || logs[0].user_id : null;
    return userId ?? OPENCTI_SYSTEM_UUID;
  });
};

export const logsTimeSeries = (context: AuthContext, user: AuthUser, args: any) => {
  const filters: any[] = args.userId ? [{ key: ['*_id'], values: [args.userId] }, ...(args.filters || [])] : args.filters;
  return timeSeriesEntities(context, user, [ENTITY_TYPE_HISTORY], { ...args, filters });
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
