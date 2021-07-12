import { BYPASS, ROLE_ADMINISTRATOR } from '../utils/access';
import { UnsupportedError } from '../config/errors';
import { shortHash, isInternalId } from '../schema/schemaUtils';
import { RULE_PREFIX } from '../schema/general';

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
