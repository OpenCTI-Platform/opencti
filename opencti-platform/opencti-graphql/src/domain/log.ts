import * as R from 'ramda';
import { elCount, elPaginate } from '../database/engine';
import conf, { booleanConf } from '../config/conf';
import { distributionHistory, timeSeriesHistory } from '../database/middleware';
import {
  INDEX_HISTORY,
  READ_INDEX_HISTORY,
} from '../database/utils';
import { ENTITY_TYPE_HISTORY } from '../schema/internalObject';
import type { AuthContext, AuthUser } from '../types/user';
import type { QueryAuditsArgs, QueryLogsArgs } from '../generated/graphql';
import type { FilterGroup } from '../database/middleware-loader';
import { addFilter } from '../utils/filtering';

export const findHistory = (context: AuthContext, user: AuthUser, args: QueryLogsArgs) => {
  const finalArgs = { ...args, orderBy: args.orderBy ?? 'timestamp', orderMode: args.orderMode ?? 'desc', types: [ENTITY_TYPE_HISTORY] };
  return elPaginate(context, user, READ_INDEX_HISTORY, finalArgs);
};

export const findAudits = (context: AuthContext, user: AuthUser, args: QueryAuditsArgs) => {
  const finalArgs = { ...args, types: args.types ? args.types : [ENTITY_TYPE_HISTORY] };
  return elPaginate(context, user, READ_INDEX_HISTORY, finalArgs);
};

export const auditsNumber = (context: AuthContext, user: AuthUser, args: any) => ({
  count: elCount(context, user, READ_INDEX_HISTORY, args),
  total: elCount(context, user, READ_INDEX_HISTORY, R.dissoc('endDate', args)),
});

export const auditsTimeSeries = (context: AuthContext, user: AuthUser, args: any) => {
  const { types } = args;
  const filters: FilterGroup = args.userId
    ? addFilter(args.filters, '*_id', args.userId)
    : args.filters;
  return timeSeriesHistory(context, user, types ?? [ENTITY_TYPE_HISTORY], { ...args, filters });
};

export const auditsMultiTimeSeries = (context: AuthContext, user: AuthUser, args: any) => {
  return Promise.all(args.timeSeriesParameters.map((timeSeriesParameter: any) => {
    const { types } = timeSeriesParameter;
    return { data: timeSeriesHistory(context, user, types ?? [ENTITY_TYPE_HISTORY], { ...args, ...timeSeriesParameter }) };
  }));
};

export const auditsDistribution = async (context: AuthContext, user: AuthUser, args: any) => {
  const { types } = args;
  return distributionHistory(context, user, types ?? [ENTITY_TYPE_HISTORY], args);
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
