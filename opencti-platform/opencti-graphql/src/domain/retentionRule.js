import { deleteElementById, updateAttribute } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { ENTITY_TYPE_RETENTION_RULE } from '../schema/internalObject';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { elIndex, elPaginate } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS, READ_DATA_INDICES_WITHOUT_INFERRED } from '../database/utils';
import { UnsupportedError } from '../config/errors';
import { utcDate } from '../utils/format';
import { RETENTION_MANAGER_USER } from '../utils/access';
import { convertFiltersToQueryOptions } from '../utils/filtering';

// 'id', 'standard_id', 'name', 'filters', 'last_execution_date', 'last_deleted_count', 'remaining_count'

export const checkRetentionRule = async (context, input) => {
  const { filters, max_retention: maxDays } = input;
  const jsonFilters = JSON.parse(filters || '{}');
  const before = utcDate().subtract(maxDays, 'days');
  const queryOptions = await convertFiltersToQueryOptions(context, jsonFilters, { before });
  const result = await elPaginate(context, RETENTION_MANAGER_USER, READ_DATA_INDICES_WITHOUT_INFERRED, queryOptions);
  return result.pageInfo.globalCount;
};

// input { name, filters }
export const createRetentionRule = async (context, user, input) => {
  // filters must be a valid json
  const { filters } = input;
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
    ...input,
  };
  await elIndex(INDEX_INTERNAL_OBJECTS, retentionRule);
  return retentionRule;
};

export const retentionRuleEditField = async (context, user, retentionRuleId, input) => {
  const { element } = await updateAttribute(context, user, retentionRuleId, ENTITY_TYPE_RETENTION_RULE, input);
  return element;
};

export const deleteRetentionRule = async (context, user, retentionRuleId) => {
  await deleteElementById(context, user, retentionRuleId, ENTITY_TYPE_RETENTION_RULE);
  return retentionRuleId;
};

export const findById = async (context, user, retentionRuleId) => {
  return storeLoadById(context, user, retentionRuleId, ENTITY_TYPE_RETENTION_RULE);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_RETENTION_RULE], args);
};
