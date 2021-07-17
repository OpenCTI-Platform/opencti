import { BYPASS, ROLE_ADMINISTRATOR } from '../utils/access';
import { UnsupportedError } from '../config/errors';
import { shortHash, isInternalId } from '../schema/schemaUtils';
import { RULE_PREFIX } from '../schema/general';
import { isEmptyField, isNotEmptyField } from '../database/utils';
import { logApp } from '../config/conf';

// region declarations
export const RULES_DECLARATION = [];
export const RULES_ATTRIBUTES_MERGE = {
  _attributes: {
    start_time: 'min',
    first_seen: 'min',
    stop_time: 'max',
    last_seen: 'max',
    confidence: 'avg',
  },
  OPERATIONS: { MIN: 'MIN', MAX: 'MAX', AVG: 'AVG', SUM: 'SUM' },
  register(rule, name, operation) {
    const meta = { rule, name, operation };
    if (isEmptyField(this.OPERATIONS[operation])) {
      throw UnsupportedError('Try to register an unsupported operation', meta);
    }
    const declaredOperation = this._attributes[name];
    if (isNotEmptyField(declaredOperation) && declaredOperation !== operation) {
      logApp.warn('Overriding attribute rule operation', meta);
    }
    this._attributes[name] = operation;
  },
  getOperation(name) {
    return this._attributes[name];
  },
  supportedAttributes() {
    return Object.keys(this._attributes);
  },
};

const RULE_MANAGER_USER_UUID = 'f9d7b43f-b208-4c56-8637-375a1ce84943';
export const RULE_MANAGER_USER = {
  id: RULE_MANAGER_USER_UUID,
  internal_id: RULE_MANAGER_USER_UUID,
  name: 'RULE MANAGER',
  user_email: 'RULE MANAGER',
  origin: {},
  roles: [{ name: ROLE_ADMINISTRATOR }],
  capabilities: [{ name: BYPASS }],
  allowed_marking: [],
};
// endregion

// region utils
export const isRuleUser = (user) => user.id === RULE_MANAGER_USER_UUID;

export const createRuleContent = (ruleId, dependencies, explanation, data = {}) => {
  if (dependencies.filter((d) => !isInternalId(d)).length > 0) {
    throw UnsupportedError('Rule definition dependencies must have internal ids only');
  }
  if (explanation.filter((d) => !isInternalId(d)).length > 0) {
    throw UnsupportedError('Rule definition explanation must have internal ids only');
  }
  const hash = shortHash(explanation);
  return { field: `${RULE_PREFIX}${ruleId}`, content: { explanation, dependencies, data, hash } };
};
// endregion
