/* eslint-disable camelcase */
import buildRelationToRelationRule from './RuleRelationInference';
import { RELATION_ATTRIBUTED_TO } from '../../schema/stixCoreRelationship';

const name = 'rule_attribution';
const description =
  'This rule will infer the following fact: if an entity A is attributed to an' +
  ' entity B and the entity B is attributed to an entity C, the entity A is also attributed to the entity C.';
const type = RELATION_ATTRIBUTED_TO;
const scopeFilters = { types: [RELATION_ATTRIBUTED_TO] };
const RuleAttributedInference = buildRelationToRelationRule(name, description, type, '*', scopeFilters);
export default RuleAttributedInference;
