import { logApp } from '../config/conf';
import { elIndex } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { generateInternalId, generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_RETENTION_RULE } from '../schema/internalObject';
import { RetentionRuleScope } from '../generated/graphql';
import { emptyFilterGroup } from '../utils/filtering/filtering-utils';

const message = '[MIGRATION] Add two built-in retention rules (on files and workbenches)';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const addRetentionRule = async (input) => {
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
  };

  const fileInput = {
    name: 'Default retention rule on files',
    scope: RetentionRuleScope.File,
    max_retention: 133,
    filters: JSON.stringify(emptyFilterGroup),
  };
  const workbenchInput = {
    name: 'Default retention rule on workbenches',
    scope: RetentionRuleScope.Workbench,
    max_retention: 60,
    filters: JSON.stringify(emptyFilterGroup),
  };
  await addRetentionRule(fileInput);
  await addRetentionRule(workbenchInput);

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
