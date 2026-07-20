import * as R from 'ramda';
import { elCount, elPaginate, elMultipleFieldCountAggregation, type PaginateOpts, elHistogramWithOutlierBinsQuery, elDateRangeCount, elCardinalityCount } from '../database/engine';
import { distributionHistory, timeSeriesHistory } from '../database/middleware';
import { INDEX_SEARCH, READ_INDEX_HISTORY, READ_INDEX_SEARCH } from '../database/utils';
import { ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY, ENTITY_TYPE_SEARCH } from '../schema/internalObject';
import type { AuthContext, AuthUser } from '../types/user';
import { OrderingMode, type QueryAuditsArgs, type QueryLogsArgs, type QuerySearchLogsArgs } from '../generated/graphql';
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
  const filters = args.userId ? addFilter(args.filters, '*_id', args.userId) : args.filters;
  return timeSeriesHistory(context, user, { ...args, historyFiltering: true, filters });
};

export const auditsMultiTimeSeries = (context: AuthContext, user: AuthUser, args: any) => {
  return Promise.all(args.timeSeriesParameters.map((timeSeriesParameter: any) => {
    return { data: timeSeriesHistory(context, user, { ...args, historyFiltering: true, ...timeSeriesParameter }) };
  }));
};

export const auditsDistribution = async (context: AuthContext, user: AuthUser, args: any) => {
  return distributionHistory(context, user, { ...args, historyFiltering: true });
};

export const findSearchLogs = (context: AuthContext, user: AuthUser, args: QuerySearchLogsArgs) => {
  const orderBy = ['organization', 'groups', 'result_count', 'search', 'search_location'].includes(args.orderBy ?? 'timestamp') ? `context_data.${args.orderBy}` : args.orderBy;
  const finalArgs = { ...args, orderBy: orderBy ?? 'timestamp', orderMode: args.orderMode ?? 'desc', types: [ENTITY_TYPE_SEARCH] };
  return elPaginate(context, user, READ_INDEX_SEARCH, finalArgs as PaginateOpts);
};

export const findSearchAnalytics = async (context: AuthContext, user: AuthUser, args: any) => {
  // return the size of the index
  const aggFields = [
    { field: 'internal_id.keyword', name: 'searches' },
    { field: 'context_data.search_location.keyword', name: 'location' },
    { field: 'context_data.organization.keyword', name: 'organization' },
    { field: 'user_id.keyword', name: 'user' },
  ];
  const noResultsFilter = {
    bool: {
      must: [
        { term: { 'context_data.result_count': 0 } },
      ],
    },
  };

  const withResultsFilter = {
    bool: {
      must_not: [
        { term: { 'context_data.result_count': 0 } },
      ],
    },
  };

  const searchAgg = await elMultipleFieldCountAggregation(context, user, INDEX_SEARCH, aggFields, { startDate: args.startDate, endDate: args.endDate });
  // return the distribution of searches grouped by contextData.search_location
  const locationResult = searchAgg.get('location') ?? [];
  const searchCount = await elDateRangeCount(context, user, INDEX_SEARCH, { startDate: args.startDate, endDate: args.endDate }) ?? 0;
  // return the distribution of searches grouped by contextData.organization
  const organizationResult = searchAgg.get('organization') ?? [];
  // gets a distinct list of users, though the list is currrently unused
  const userResult = searchAgg.get('user') ?? [];
  const histogramResult: { bin: string; count: number }[] = await elHistogramWithOutlierBinsQuery(context, user, INDEX_SEARCH, { field: 'context_data.result_count', name: 'results' }, { startDate: args.startDate, endDate: args.endDate }, args.binSize, args.minBin, args.maxBin);
  const searchTermsWithResults = await elMultipleFieldCountAggregation(context, user, INDEX_SEARCH, [{ field: 'context_data.search.keyword', name: 'search' }], { startDate: args.startDate, endDate: args.endDate, first: args.first }, withResultsFilter);
  const searchTermsWithNoResults = await elMultipleFieldCountAggregation(context, user, INDEX_SEARCH, [{ field: 'context_data.search.keyword', name: 'search' }], { startDate: args.startDate, endDate: args.endDate, first: args.first }, noResultsFilter);
  const response = {
    summary: { total_searches: searchCount, total_locations: locationResult.length, total_organizations: organizationResult.length, total_users: userResult.length },
    locations: locationResult,
    organizations: organizationResult,
    searchCounts: histogramResult,
    withResults: searchTermsWithResults.get('search'),
    noResults: searchTermsWithNoResults.get('search'),
  };
  return response;
};
