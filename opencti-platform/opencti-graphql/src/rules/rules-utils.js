import * as R from 'ramda';
import { UnsupportedError } from '../config/errors';
import { isInternalId, shortHash } from '../schema/schemaUtils';
import { RULE_PREFIX } from '../schema/general';
import { RULE_MANAGER_USER_UUID } from '../utils/access';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { isStixCoreObject } from '../schema/stixCoreObject';
import { isBasicRelationship } from '../schema/stixRelationship';
import { ENTITY_TYPE_INCIDENT } from '../schema/stixDomainObject';

// region definition
export const RULES_ATTRIBUTES_BEHAVIOR = {
  OPERATIONS: { MIN: 'MIN', MAX: 'MAX', AVG: 'AVG', SUM: 'SUM', AGG: 'AGG' },
  supportedAttributes(entityType) {
    if (isStixSightingRelationship(entityType)) {
      return [
        { name: 'first_seen', operation: 'MIN' },
        { name: 'last_seen', operation: 'MAX' },
        { name: 'confidence', operation: 'AVG' },
        { name: 'attribute_count', operation: 'SUM' },
        { name: 'objectMarking', operation: 'AGG' },
      ];
    }
    if (isBasicRelationship(entityType)) {
      return [
        { name: 'start_time', operation: 'MIN' },
        { name: 'stop_time', operation: 'MAX' },
        { name: 'confidence', operation: 'AVG' },
        { name: 'objectMarking', operation: 'AGG' },
      ];
    }
    if (entityType === ENTITY_TYPE_INCIDENT) { // RuleSightingIncident
      return [
        { name: 'first_seen', operation: 'MIN' },
        { name: 'last_seen', operation: 'MAX' },
        { name: 'confidence', operation: 'AVG' },
        { name: 'objectMarking', operation: 'AGG' },
      ];
    }
    if (isStixCoreObject(entityType)) {
      return [{ name: 'objectMarking', operation: 'AGG' }];
    }
    return [];
  },
};
// endregion

// region utils
export const isRuleUser = (user) => user.id === RULE_MANAGER_USER_UUID;

export const createRuleContent = (ruleId, dependencies, explanation, data = {}) => {
  if (dependencies.filter((d) => !isInternalId(R.head(d.split('_')))).length > 0) {
    throw UnsupportedError('Rule definition dependencies must have internal ids only');
  }
  if (explanation.filter((d) => !isInternalId(R.head(d.split('_')))).length > 0) {
    throw UnsupportedError('Rule definition explanation must have internal ids only');
  }
  const hash = shortHash(explanation);
  return { field: `${RULE_PREFIX}${ruleId}`, content: { explanation, dependencies, data, hash } };
};
// endregion
