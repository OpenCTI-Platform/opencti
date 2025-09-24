import * as R from 'ramda';
import { elCount, elPaginate } from '../database/engine';
import conf, { booleanConf } from '../config/conf';
import { distributionHistory, timeSeriesHistory } from '../database/middleware';
import { INDEX_HISTORY, READ_INDEX_HISTORY, } from '../database/utils';
import { ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY } from '../schema/internalObject';
import type { AuthContext, AuthUser } from '../types/user';
import type { QueryAuditsArgs, QueryLogsArgs } from '../generated/graphql';
import { addFilter } from '../utils/filtering/filtering-utils';
import { isUserHasCapability, KNOWLEDGE, SETTINGS_SECURITYACTIVITY } from '../utils/access';
import { ForbiddenAccess } from '../config/errors';

export const findHistory = (context: AuthContext, user: AuthUser, args: QueryLogsArgs) => {
  const finalArgs = { ...args, orderBy: args.orderBy ?? 'timestamp', orderMode: args.orderMode ?? 'desc', types: [ENTITY_TYPE_HISTORY] };
  return elPaginate(context, user, READ_INDEX_HISTORY, finalArgs);
};

export const findAudits = (context: AuthContext, user: AuthUser, args: QueryAuditsArgs) => {
  // eslint-disable-next-line no-nested-ternary
  let types = args.types ? args.types : isUserHasCapability(user, SETTINGS_SECURITYACTIVITY) ? [ENTITY_TYPE_ACTIVITY] : [ENTITY_TYPE_HISTORY];
  if (!isUserHasCapability(user, KNOWLEDGE)) {
    types = types.filter((t) => t !== ENTITY_TYPE_HISTORY);
  }
  if (!isUserHasCapability(user, SETTINGS_SECURITYACTIVITY)) {
    types = types.filter((t) => t !== ENTITY_TYPE_ACTIVITY);
  }
  if (types.length === 0) {
    throw ForbiddenAccess();
  }
  const finalArgs = { ...args, types };
  return elPaginate(context, user, READ_INDEX_HISTORY, finalArgs);
};

export const auditsNumber = (context: AuthContext, user: AuthUser, args: any) => ({
  count: elCount(context, user, READ_INDEX_HISTORY, args),
  total: elCount(context, user, READ_INDEX_HISTORY, R.dissoc('endDate', args)),
});

export const auditsTimeSeries = (context: AuthContext, user: AuthUser, args: any) => {
  const { types } = args;
  const filters = args.userId
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

export const auditsMultiDistribution = async (context: AuthContext, user: AuthUser, args: any) => {
  return Promise.all(args.distributionParameters.map((distributionParameterSet: any) => {
    const { types } = distributionParameterSet;
    return { data: distributionHistory(context, user, types ?? [ENTITY_TYPE_HISTORY], { ...args, ...distributionParameterSet }) };
  }));
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
