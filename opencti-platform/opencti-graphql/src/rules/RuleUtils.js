import * as R from 'ramda';
import { RULE_PREFIX } from '../schema/general';
import { isNotEmptyField } from '../database/utils';
import declaredDef from './RuleDefinitions';

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
