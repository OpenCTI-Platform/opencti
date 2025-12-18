import * as R from 'ramda';
import { elCount, elPaginate, type PaginateOpts } from '../database/engine';
import conf, { booleanConf } from '../config/conf';
import { distributionHistory, timeSeriesHistory } from '../database/middleware';
import { INDEX_HISTORY, READ_INDEX_HISTORY } from '../database/utils';
import { ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY } from '../schema/internalObject';
import type { AuthContext, AuthUser } from '../types/user';
import { OrderingMode, type QueryAuditsArgs, type QueryLogsArgs } from '../generated/graphql';
import { addFilter } from '../utils/filtering/filtering-utils';
import { isUserHasCapability, KNOWLEDGE, SETTINGS_SECURITYACTIVITY } from '../utils/access';
import { ForbiddenAccess } from '../config/errors';
import type { BasicStoreEntity } from '../types/store';
import { type EntityOptions, pageEntitiesConnection, storeLoadById } from '../database/middleware-loader';
import type { Change } from '../types/event';

interface StoreHistory extends BasicStoreEntity {
  context_data: {
    message: string;
    entity_type: string;
    history_changes: Change[];
  };
}

export const findHistory = async (context: AuthContext, user: AuthUser, args: QueryLogsArgs) => {
  const finalArgs: EntityOptions<StoreHistory> = {
    ...args,
    historyFiltering: true,
    orderBy: args.orderBy ?? 'timestamp',
    orderMode: args.orderMode ?? OrderingMode.Desc,
  };
  return pageEntitiesConnection(context, user, [ENTITY_TYPE_HISTORY], finalArgs);
};

export const findById = async (context: AuthContext, user: AuthUser, logId: string) => {
  return storeLoadById(context, user, logId, ENTITY_TYPE_HISTORY, { historyFiltering: true });
};

export const findAudits = (context: AuthContext, user: AuthUser, args: QueryAuditsArgs) => {
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
  const finalArgs = { ...args, types, historyFiltering: true };
  return elPaginate(context, user, READ_INDEX_HISTORY, finalArgs as PaginateOpts);
};

export const findAuditById = async (context: AuthContext, user: AuthUser, auditId: string) => {
  const types = [];
  if (isUserHasCapability(user, KNOWLEDGE)) {
    types.push(ENTITY_TYPE_HISTORY);
  }
  if (isUserHasCapability(user, SETTINGS_SECURITYACTIVITY)) {
    types.push(ENTITY_TYPE_ACTIVITY);
  }
  if (types.length === 0) {
    throw ForbiddenAccess();
  }
  return storeLoadById(context, user, auditId, types, { historyFiltering: true });
};

export const auditsNumber = (context: AuthContext, user: AuthUser, args: any) => {
  const finalArgs = { ...args, historyFiltering: true };
  return {
    count: elCount(context, user, READ_INDEX_HISTORY, finalArgs),
    total: elCount(context, user, READ_INDEX_HISTORY, R.dissoc('endDate', finalArgs)),
  };
};

export const auditsTimeSeries = (context: AuthContext, user: AuthUser, args: any) => {
  const { types } = args;
  const filters = args.userId
    ? addFilter(args.filters, '*_id', args.userId)
    : args.filters;
  return timeSeriesHistory(context, user, types ?? [ENTITY_TYPE_HISTORY], { ...args, historyFiltering: true, filters });
};

export const auditsMultiTimeSeries = (context: AuthContext, user: AuthUser, args: any) => {
  return Promise.all(args.timeSeriesParameters.map((timeSeriesParameter: any) => {
    const { types } = timeSeriesParameter;
    return { data: timeSeriesHistory(context, user, types ?? [ENTITY_TYPE_HISTORY], { ...args, historyFiltering: true, ...timeSeriesParameter }) };
  }));
};

export const auditsDistribution = async (context: AuthContext, user: AuthUser, args: any) => {
  const { types } = args;
  return distributionHistory(context, user, types ?? [ENTITY_TYPE_HISTORY], { ...args, historyFiltering: true });
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
