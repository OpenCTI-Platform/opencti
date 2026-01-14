/* eslint-disable camelcase */
import buildRelationToRelationRule from '../relationToRelationBuilder';
import { RELATION_ATTRIBUTED_TO, RELATION_INDICATES } from '../../schema/stixCoreRelationship';
import def from './AttributionIndicatorIndicatesDefinition';

/**
 * Rule: If Entity A attributed to Entity B, If Indicator C indicates Entity A,
 * Then Indicator C indicates Entity B
 *
 * Pattern:
 * - C indicates A (leftType)
 * - A attributed-to B (rightType)
 * - Result: C indicates B (creationType)
 */
const AttributionIndicatorIndicatesRule = buildRelationToRelationRule(def, {
  leftType: RELATION_INDICATES,
  rightType: RELATION_ATTRIBUTED_TO,
  creationType: RELATION_INDICATES,
});

export default AttributionIndicatorIndicatesRule;
