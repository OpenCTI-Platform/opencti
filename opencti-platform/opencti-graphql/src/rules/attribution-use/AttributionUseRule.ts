/* eslint-disable camelcase */
import { RELATION_ATTRIBUTED_TO, RELATION_USES } from '../../schema/stixCoreRelationship';
import def from './AttributionUseDefinition';
import buildRelationWithRelationRule from '../relationWithRelationBuilder';
import { RULES } from '../rules';

const AttributionUseRule = buildRelationWithRelationRule(def, {
  leftType: RELATION_USES,
  rightType: RELATION_ATTRIBUTED_TO,
  creationType: RELATION_USES,
});

RULES.push(AttributionUseRule);
export default AttributionUseRule;
