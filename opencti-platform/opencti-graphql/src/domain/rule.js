import * as R from 'ramda';
import { listEntities } from '../database/middleware';
import { SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_RULE } from '../schema/internalObject';
import declaredRules from '../rules/RuleDeclarations';
import { isNotEmptyField } from '../database/utils';

export const getRules = async () => {
  const args = { connectionFormat: false, filters: [{ key: 'active', values: [true] }] };
  const rules = await listEntities(SYSTEM_USER, [ENTITY_TYPE_RULE], args);
  return declaredRules.map((d) => {
    const esRule = R.find((e) => e.internal_id === d.id)(rules);
    const isActivated = isNotEmptyField(esRule) && esRule.active;
    return { ...d, activated: isActivated };
  });
};
export const getActivatedRules = async () => {
  const rules = await getRules();
  return rules.filter((r) => r.activated);
};
export const getRule = async (id) => {
  const rules = await getRules();
  return R.find((e) => e.id === id)(rules);
};
