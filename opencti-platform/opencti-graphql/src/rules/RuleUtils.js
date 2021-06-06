import { isNotEmptyField } from '../database/utils';
import { RULE_PREFIX } from '../schema/general';

export const createRulePatch = (rule, dependencies, explanation, inferred = {}) => {
  const content = { explanation, dependencies };
  if (isNotEmptyField(inferred)) {
    content.inferred = inferred;
  }
  return { [`${RULE_PREFIX}${rule}`]: content };
};

export const createClearRulePatch = (rule) => ({ [`${RULE_PREFIX}${rule}`]: null });
