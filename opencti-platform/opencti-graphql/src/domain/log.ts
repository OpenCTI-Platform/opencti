import { elPaginate } from '../database/engine';
import conf, { booleanConf } from '../config/conf';
import {timeSeriesAudits, timeSeriesEntities, timeSeriesHistories} from '../database/middleware';
import { INDEX_HISTORY, READ_INDEX_HISTORY } from '../database/utils';
import { ENTITY_TYPE_HISTORY } from '../schema/internalObject';
import type { AuthContext, AuthUser } from '../types/user';
import type { QueryAuditsArgs, QueryLogsArgs } from '../generated/graphql';
import {ABSTRACT_STIX_CORE_OBJECT} from "../schema/general";

export const findHistory = (context: AuthContext, user: AuthUser, args: QueryLogsArgs) => {
  const finalArgs = { ...args, orderBy: args.orderBy ?? 'timestamp', orderMode: args.orderMode ?? 'desc', types: [ENTITY_TYPE_HISTORY] };
  return elPaginate(context, user, READ_INDEX_HISTORY, finalArgs);
};

export const findAudits = (context: AuthContext, user: AuthUser, args: QueryAuditsArgs) => {
  const finalArgs = { ...args, types: args.types ? args.types : [ENTITY_TYPE_HISTORY] };
  return elPaginate(context, user, READ_INDEX_HISTORY, finalArgs);
};

export const logsTimeSeries = (context: AuthContext, user: AuthUser, args: any) => {
  const filters: any[] = args.userId ? [{ key: ['*_id'], values: [args.userId] }, ...(args.filters || [])] : args.filters;
  return timeSeriesHistories(context, user, { ...args, filters });
};

export const auditsTimeSeries = (context: AuthContext, user: AuthUser, args: any) => {
  const { types } = args;
  const filters: any[] = args.userId ? [{ key: ['*_id'], values: [args.userId] }, ...(args.filters || [])] : args.filters;
  return timeSeriesAudits(context, user, types ?? [ENTITY_TYPE_HISTORY], { ...args, filters });
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
