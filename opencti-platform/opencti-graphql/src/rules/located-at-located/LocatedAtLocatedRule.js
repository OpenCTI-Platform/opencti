/* eslint-disable camelcase */
import buildRelationToRelationRule from '../relationToRelationBuilder';
import { RELATION_LOCATED_AT } from '../../schema/stixCoreRelationship';
import def from './LocatedAtLocatedDefinition';

const LocatedAtLocatedRule = buildRelationToRelationRule(def, {
  leftType: RELATION_LOCATED_AT,
  rightType: RELATION_LOCATED_AT,
  creationType: RELATION_LOCATED_AT,
});

export default LocatedAtLocatedRule;
