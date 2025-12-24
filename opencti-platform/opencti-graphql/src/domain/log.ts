import * as R from 'ramda';
import { elCount, elPaginate, type PaginateOpts } from '../database/engine';
import conf, { booleanConf } from '../config/conf';
import { distributionHistory, timeSeriesHistory } from '../database/middleware';
import { INDEX_HISTORY, isNotEmptyField, READ_INDEX_HISTORY } from '../database/utils';
import { ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY } from '../schema/internalObject';
import type { AuthContext, AuthUser } from '../types/user';
import { OrderingMode, type QueryAuditsArgs, type QueryLogsArgs } from '../generated/graphql';
import { addFilter } from '../utils/filtering/filtering-utils';
import { isUserHasCapability, KNOWLEDGE, SETTINGS_SECURITYACTIVITY } from '../utils/access';
import { ForbiddenAccess } from '../config/errors';
import type { BasicStoreEntity } from '../types/store';
import { type EntityOptions, pageEntitiesConnection } from '../database/middleware-loader';
import type { Change } from '../types/event';
import { MAX_OPERATIONS_FOR_MESSAGE } from '../database/generate-message';
import { schemaAttributesDefinition } from '../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';

interface StoreHistory extends BasicStoreEntity {
  context_data: {
    message: string;
    entity_type: string;
    changes: Change[];
  };
}

const filterChangesForUser = (user: AuthUser, entityType: string, changes: Change[]): Change[] => {
  const validChanges = [];
  for (let index = 0; index < changes.length; index += 1) {
    const { field } = changes[index];
    const attributeDefinition = schemaAttributesDefinition.getAttribute(entityType, field);
    const relationsRefDefinition = schemaRelationsRefDefinition.getRelationRef(entityType, field);
    const changeAttribute = attributeDefinition ?? relationsRefDefinition;
    const capabilities = changeAttribute?.requiredCapabilities ?? [];
    const userHaveCapability = capabilities.every((capability) => isUserHasCapability(user, capability));
    if (userHaveCapability) {
      validChanges.push(changes[index]);
    }
  }
  return validChanges;
};

const generateMessageFromChanges = (changes: Change[]) => {
  const sliceChanges = changes.slice(0, MAX_OPERATIONS_FOR_MESSAGE);
  let newMessage = sliceChanges.map((c) => {
    let values = c.new;
    let action = 'replaces';
    if ((c.added ?? []).length > 0) {
      action = 'adds';
      values = c.added;
    } else if ((c.removed ?? []).length > 0) {
      action = 'removes';
      values = c.removed;
    }
    const vals = values ?? [];
    let displayValues = vals.slice(0, 2).join(', ');
    if (vals.length > 2) {
      displayValues += ', ...';
    }
    return action + ' `' + displayValues + '` in `' + c.field + '`';
  }).join(' - ');
  if (changes.length > MAX_OPERATIONS_FOR_MESSAGE) {
    newMessage += ' and ' + (changes.length - MAX_OPERATIONS_FOR_MESSAGE) + ' more operations';
  }
  return newMessage;
};

export const findHistory = async (context: AuthContext, user: AuthUser, args: QueryLogsArgs) => {
  const finalArgs: EntityOptions<StoreHistory> = { ...args, orderBy: args.orderBy ?? 'timestamp', orderMode: args.orderMode ?? OrderingMode.Desc };
  const historyLines = await pageEntitiesConnection(context, user, [ENTITY_TYPE_HISTORY], finalArgs);
  // Rewrite history lines to hide restricted changes
  historyLines.edges.forEach((edge) => {
    const changes = edge.node.context_data.changes;
    if (isNotEmptyField(changes)) {
      // Filter changes related to the user rights
      const validChanges = filterChangesForUser(user, edge.node.context_data.entity_type, changes);
      // Test if user have access to at least 1 change
      if (validChanges.length === 0) {
        edge.node.context_data.message = '- `restricted changes`';
        edge.node.context_data.changes = [];
      } else {
        // Generate message
        edge.node.context_data.message = generateMessageFromChanges(validChanges);
      }
    }
  });
  return historyLines;
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
  const finalArgs = { ...args, types };
  return elPaginate(context, user, READ_INDEX_HISTORY, finalArgs as PaginateOpts);
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
