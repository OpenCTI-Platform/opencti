import * as R from 'ramda';
import { elCount, elPaginate, type PaginateOpts, elCardinalityCount } from '../database/engine';
import { distributionHistory, timeSeriesHistory } from '../database/middleware';
import { READ_INDEX_HISTORY } from '../database/utils';
import { ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY } from '../schema/internalObject';
import type { AuthContext, AuthUser } from '../types/user';
import { OrderingMode, type QueryAuditsArgs, type QueryLogsArgs } from '../generated/graphql';
import { addFilter } from '../utils/filtering/filtering-utils';
import { isUserHasCapability, KNOWLEDGE, SETTINGS_SECURITYACTIVITY } from '../utils/access';
import { ForbiddenAccess } from '../config/errors';
import type { BasicStoreEntity } from '../types/store';
import { type EntityOptions, pageEntitiesConnection, storeLoadById } from '../database/middleware-loader';
import type { Change } from '../types/event';

export interface StoreHistory extends BasicStoreEntity {
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
  return storeLoadById<StoreHistory>(context, user, logId, ENTITY_TYPE_HISTORY, { historyFiltering: true });
};

export const computeAuditTypes = (user: AuthUser, requestedTypes?: string[] | null): string[] => {
  let types = requestedTypes && requestedTypes.length > 0
    ? requestedTypes
    : (isUserHasCapability(user, SETTINGS_SECURITYACTIVITY) ? [ENTITY_TYPE_ACTIVITY] : [ENTITY_TYPE_HISTORY]);
  if (!isUserHasCapability(user, KNOWLEDGE)) {
    types = types.filter((t) => t !== ENTITY_TYPE_HISTORY);
  }
  if (!isUserHasCapability(user, SETTINGS_SECURITYACTIVITY)) {
    types = types.filter((t) => t !== ENTITY_TYPE_ACTIVITY);
  }
  if (types.length === 0) {
    throw ForbiddenAccess();
  }
  return types;
};

export const findAudits = (context: AuthContext, user: AuthUser, args: QueryAuditsArgs) => {
  const types = computeAuditTypes(user, args.types);
  const finalArgs = { ...args, types, historyFiltering: true };
  return elPaginate(context, user, READ_INDEX_HISTORY, finalArgs as PaginateOpts);
};

export const findAuditById = async (context: AuthContext, user: AuthUser, auditId: string) => {
  const types = computeAuditTypes(user);
  return storeLoadById(context, user, auditId, types, { historyFiltering: true });
};

export const auditsNumber = (context: AuthContext, user: AuthUser, args: any) => {
  const types = computeAuditTypes(user, args.types);
  const finalArgs = { ...args, types, historyFiltering: true };
  if (args.unique) {
    return {
      count: elCardinalityCount(context, user, READ_INDEX_HISTORY, args.field, finalArgs),
      total: elCardinalityCount(context, user, READ_INDEX_HISTORY, args.field, R.dissoc('endDate', finalArgs)),
    };
  } else {
    return {
      count: elCount(context, user, READ_INDEX_HISTORY, finalArgs),
      total: elCount(context, user, READ_INDEX_HISTORY, R.dissoc('endDate', finalArgs)),
    };
  }
};

export const auditsTimeSeries = (context: AuthContext, user: AuthUser, args: any) => {
  const types = computeAuditTypes(user, args.types);
  const filters = args.userId ? addFilter(args.filters, '*_id', args.userId) : args.filters;
  return timeSeriesHistory(context, user, { ...args, types, historyFiltering: true, filters });
};

export const auditsMultiTimeSeries = (context: AuthContext, user: AuthUser, args: any) => {
  return Promise.all(args.timeSeriesParameters.map((timeSeriesParameter: any) => {
    const types = computeAuditTypes(user, timeSeriesParameter.types);
    return { data: timeSeriesHistory(context, user, { ...args, historyFiltering: true, ...timeSeriesParameter, types }) };
  }));
};

export const auditsDistribution = async (context: AuthContext, user: AuthUser, args: any) => {
  const types = computeAuditTypes(user, args.types);
  return distributionHistory(context, user, { ...args, types, historyFiltering: true });
};
