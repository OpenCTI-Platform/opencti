/* eslint-disable camelcase */
import buildRelationToRelationRule from '../relationToRelationBuilder';
import { RELATION_LOCATED_AT } from '../../schema/stixCoreRelationship';
import def from './LocatedAtLocatedDefinition';
import { RULES_DECLARATION } from '../rules';

const LocatedAtLocatedRule = buildRelationToRelationRule(def, {
  leftType: RELATION_LOCATED_AT,
  rightType: RELATION_LOCATED_AT,
  creationType: RELATION_LOCATED_AT,
});

RULES_DECLARATION.push(LocatedAtLocatedRule);
export default LocatedAtLocatedRule;
