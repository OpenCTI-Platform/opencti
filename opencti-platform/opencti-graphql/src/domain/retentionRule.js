import { deleteElementById, updateAttribute } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { ENTITY_TYPE_RETENTION_RULE } from '../schema/internalObject';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { elIndex, elPaginate } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS, READ_STIX_INDICES } from '../database/utils';
import { UnsupportedError } from '../config/errors';
import { utcDate } from '../utils/format';
import { RETENTION_MANAGER_USER } from '../utils/access';
import { convertFiltersToQueryOptions } from '../utils/filtering/filtering-resolution';
import { publishUserAction } from '../listener/UserActionListener';
import { DELETABLE_FILE_STATUSES, paginatedForPathWithEnrichment } from '../modules/internal/document/document-domain';
import { logApp } from '../config/conf';

export const checkRetentionRule = async (context, input) => {
  const { filters, max_retention: maxDays, scope, retention_unit: unit } = input;
  const before = utcDate().subtract(maxDays, unit ?? 'days');
  let result = [];
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
    result = await paginatedForPathWithEnrichment(context, RETENTION_MANAGER_USER, 'import/pending', undefined, { notModifiedSince: before.toISOString() });
  } else {
    logApp.error(`[Retention manager] Scope ${scope} not existing for Retention Rule.`);
  }
  if (scope === 'file' || scope === 'workbench') { // don't delete progress files or files with works in progress
    result.edges = result.edges.filter((e) => DELETABLE_FILE_STATUSES.includes(e.node.uploadStatus)
        && (e.node.works ?? []).every((work) => !work || DELETABLE_FILE_STATUSES.includes(work?.status)));
  }
  return result.edges.length;
};

// input { name, filters }
export const createRetentionRule = async (_, user, input) => {
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
    last_execution_date: null,
    last_deleted_count: null,
    remaining_count: null,
    retention_unit: input.retention_unit ?? 'days',
    filters,
    ...input,
  };
  await elIndex(INDEX_INTERNAL_OBJECTS, retentionRule);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates retention rule \`${retentionRule.name}\``,
    context_data: { id: retentionRuleId, entity_type: ENTITY_TYPE_RETENTION_RULE, input }
  });
  return retentionRule;
};

export const retentionRuleEditField = async (context, user, retentionRuleId, input) => {
  const { element } = await updateAttribute(context, user, retentionRuleId, ENTITY_TYPE_RETENTION_RULE, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for retention rule \`${element.name}\``,
    context_data: { id: retentionRuleId, entity_type: ENTITY_TYPE_RETENTION_RULE, input }
  });
  return element;
};

export const deleteRetentionRule = async (context, user, retentionRuleId) => {
  const deleted = await deleteElementById(context, user, retentionRuleId, ENTITY_TYPE_RETENTION_RULE);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes retention rule \`${deleted.name}\``,
    context_data: { id: retentionRuleId, entity_type: ENTITY_TYPE_RETENTION_RULE, input: deleted }
  });
  return retentionRuleId;
};

export const findById = async (context, user, retentionRuleId) => {
  return storeLoadById(context, user, retentionRuleId, ENTITY_TYPE_RETENTION_RULE);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_RETENTION_RULE], args);
};
