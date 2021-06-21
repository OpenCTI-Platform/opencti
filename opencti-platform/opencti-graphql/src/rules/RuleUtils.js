import * as R from 'ramda';
import { RULE_PREFIX } from '../schema/general';
import { isNotEmptyField } from '../database/utils';
import declaredDef from './RuleDefinitions';
import { BYPASS, ROLE_ADMINISTRATOR } from '../utils/access';

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

export const getAttributesRulesFor = (attrKey) => {
  const attrRules = declaredDef.filter((d) => d.scopeFields.includes(attrKey));
  return R.flatten(attrRules.map((r) => `${RULE_PREFIX + r.id}.inferred.${attrKey}`));
};

export const createRulePatch = (rule, dependencies, explanation, inferred = {}) => {
  const content = { explanation, dependencies };
  if (isNotEmptyField(inferred)) {
    content.inferred = inferred;
  }
  return { [`${RULE_PREFIX}${rule}`]: content };
};

export const createClearRulePatch = (rule) => ({ [`${RULE_PREFIX}${rule}`]: null });
