import { deleteElementById, updateAttribute } from '../../database/middleware';
import { topEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_RETENTION_RULE, type BasicStoreEntityRetentionRule } from './retentionRules-types';
import { generateInternalId, generateStandardId } from '../../schema/identifier';
import { elIndex, elPaginate } from '../../database/engine';
import { INDEX_INTERNAL_OBJECTS, READ_INDEX_HISTORY, READ_STIX_INDICES } from '../../database/utils';
import { UnsupportedError } from '../../config/errors';
import { utcDate } from '../../utils/format';
import { RETENTION_MANAGER_USER } from '../../utils/access';
import { convertFiltersToQueryOptions } from '../../utils/filtering/filtering-resolution';
import { publishUserAction } from '../../listener/UserActionListener';
import { DELETABLE_FILE_STATUSES, paginatedForPathWithEnrichment } from '../internal/document/document-domain';
import { FEATURE_ACTIVITY_HISTORY_RETENTION, isFeatureEnabled, logApp } from '../../config/conf';
import { BASE_TYPE_ENTITY } from '../../schema/general';
import { getParentTypes } from '../../schema/schemaUtils';
import type { AuthContext, AuthUser } from '../../types/user';
import type { EditInput, QueryRetentionRulesArgs, RetentionRuleAddInput } from '../../generated/graphql';
import { ENTITY_TYPE_HISTORY } from '../../schema/internalObject';

export const checkRetentionRule = async (context: AuthContext, input: RetentionRuleAddInput) => {
  const { filters, max_retention: maxDays, scope, retention_unit: unit } = input;
  if (scope === 'history' && !isFeatureEnabled(FEATURE_ACTIVITY_HISTORY_RETENTION)) {
    throw UnsupportedError('The history scope for retention rules is not enabled on this platform');
  }
  const before = utcDate().subtract(maxDays, unit ?? 'days');
  let result: any = [];
  // knowledge rule
  if (scope === 'knowledge') {
    const jsonFilters = filters ? JSON.parse(filters) : null;
    const queryOptions = await convertFiltersToQueryOptions(jsonFilters, { before });
    result = await elPaginate(context, RETENTION_MANAGER_USER, READ_STIX_INDICES, { ...queryOptions, first: 1 });
    return result.pageInfo.globalCount;
  }
  // file and workbench rules
  if (scope === 'file') {
    result = await paginatedForPathWithEnrichment(context, RETENTION_MANAGER_USER, 'import/global', undefined, { notModifiedSince: before.toISOString() });
  } else if (scope === 'workbench') {
    // exact_path: false to get ALL workbenches (both global and entity-attached)
    result = await paginatedForPathWithEnrichment(context, RETENTION_MANAGER_USER, 'import/pending', undefined, { notModifiedSince: before.toISOString(), exact_path: false });
  } else if (scope === 'history') {
    const jsonFilters = filters ? JSON.parse(filters) : null;
    const queryOptions = await convertFiltersToQueryOptions(jsonFilters, { before });
    result = await elPaginate(context, RETENTION_MANAGER_USER, READ_INDEX_HISTORY, { ...queryOptions, types: [ENTITY_TYPE_HISTORY], first: 1 });
    return result.pageInfo.globalCount;
  } else {
    logApp.error('[Retention manager] Scope not existing for Retention Rule.', { scope });
  }
  if (scope === 'file' || scope === 'workbench') { // don't delete progress files or files with works in progress
    result.edges = result.edges.filter((e: any) => DELETABLE_FILE_STATUSES.includes(e.node.uploadStatus)
      && (e.node.works ?? []).every((work: any) => !work || DELETABLE_FILE_STATUSES.includes(work?.status)));
  }
  return result.edges.length;
};

// input { name, filters }
export const createRetentionRule = async (context: AuthContext, user: AuthUser, input: RetentionRuleAddInput) => {
  // filters must be a valid json
  let { filters } = input;
  if (!filters) { // filters is undefined or an empty string
    filters = JSON.stringify({ mode: 'and', filters: [], filterGroups: [] });
  }
  try {
    JSON.parse(filters);
  } catch {
    throw UnsupportedError('Retention rule must have valid filters');
  }
  // create the retention rule
  const retentionRuleId = generateInternalId();
  const retentionRule = {
    id: retentionRuleId,
    internal_id: retentionRuleId,
    standard_id: generateStandardId(ENTITY_TYPE_RETENTION_RULE, input),
    entity_type: ENTITY_TYPE_RETENTION_RULE,
    base_type: BASE_TYPE_ENTITY,
    parent_types: getParentTypes(ENTITY_TYPE_RETENTION_RULE),
    last_execution_date: null,
    last_deleted_count: null,
    remaining_count: null,
    retention_unit: input.retention_unit ?? 'days',
    ...input,
    filters,
  };
  await elIndex(INDEX_INTERNAL_OBJECTS, retentionRule);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates retention rule \`${retentionRule.name}\``,
    context_data: { id: retentionRuleId, entity_type: ENTITY_TYPE_RETENTION_RULE, input },
  });
  return retentionRule;
};

export const retentionRuleEditField = async (context: AuthContext, user: AuthUser, retentionRuleId: string, input: EditInput[]) => {
  const { element } = await updateAttribute(context, user, retentionRuleId, ENTITY_TYPE_RETENTION_RULE, input);
  const retentionElement = element as unknown as BasicStoreEntityRetentionRule;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for retention rule \`${retentionElement.name}\``,
    context_data: { id: retentionRuleId, entity_type: ENTITY_TYPE_RETENTION_RULE, input },
  });
  return element;
};

export const deleteRetentionRule = async (context: AuthContext, user: AuthUser, retentionRuleId: string) => {
  const deleted = await deleteElementById(context, user, retentionRuleId, ENTITY_TYPE_RETENTION_RULE);
  const deletedElement = deleted as unknown as BasicStoreEntityRetentionRule;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes retention rule \`${deletedElement.name}\``,
    context_data: { id: retentionRuleId, entity_type: ENTITY_TYPE_RETENTION_RULE, input: deleted },
  });
  return retentionRuleId;
};

export const findById = async (context: AuthContext, user: AuthUser, retentionRuleId: string) => {
  return storeLoadById<BasicStoreEntityRetentionRule>(context, user, retentionRuleId, ENTITY_TYPE_RETENTION_RULE);
};

export const findRetentionRulePaginated = (context: AuthContext, user: AuthUser, args: QueryRetentionRulesArgs) => {
  return pageEntitiesConnection<BasicStoreEntityRetentionRule>(context, user, [ENTITY_TYPE_RETENTION_RULE], args);
};

export const listRules = (context: AuthContext, user: AuthUser, args?: any) => {
  return topEntitiesList<BasicStoreEntityRetentionRule>(context, user, [ENTITY_TYPE_RETENTION_RULE], args);
};
