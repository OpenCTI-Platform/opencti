import { deleteElementById, listEntities, loadById, updateAttribute } from '../database/middleware';
import { ENTITY_TYPE_RETENTION_RULE } from '../schema/internalObject';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { elIndex } from '../database/elasticSearch';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { UnsupportedError } from '../config/errors';

// 'id', 'standard_id', 'name', 'filters', 'last_execution_date', 'last_deleted_count'

// input { name, filters }
export const createRetentionRule = async (user, input) => {
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
    ...input,
  };
  await elIndex(INDEX_INTERNAL_OBJECTS, retentionRule);
  return retentionRule;
};

export const retentionRuleEditField = async (user, retentionRuleId, input) => {
  const { element } = await updateAttribute(user, retentionRuleId, ENTITY_TYPE_RETENTION_RULE, input);
  return element;
};

export const deleteRetentionRule = async (user, retentionRuleId) => {
  await deleteElementById(user, retentionRuleId, ENTITY_TYPE_RETENTION_RULE);
  return retentionRuleId;
};

export const findById = async (user, retentionRuleId) => {
  return loadById(user, retentionRuleId, ENTITY_TYPE_RETENTION_RULE);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_RETENTION_RULE], args);
};
