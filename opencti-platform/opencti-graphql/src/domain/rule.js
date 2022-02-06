import * as R from 'ramda';
import { listEntities } from '../database/repository';
import { SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_RULE } from '../schema/internalObject';
import { isNotEmptyField } from '../database/utils';
import { RULES_DECLARATION } from '../rules/rules';

export const getRules = async () => {
  const args = { connectionFormat: false, filters: [{ key: 'active', values: [true] }] };
  const rules = await listEntities(SYSTEM_USER, [ENTITY_TYPE_RULE], args);
  return RULES_DECLARATION.map((d) => {
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
