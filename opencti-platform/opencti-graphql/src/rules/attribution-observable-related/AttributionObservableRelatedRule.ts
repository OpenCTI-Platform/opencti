/* eslint-disable camelcase */
import buildRelationToRelationRule from '../relationToRelationBuilder';
import { RELATION_ATTRIBUTED_TO, RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import def from './AttributionObservableRelatedDefinition';

/**
 * Rule: If Entity A attributed to Entity B, If Observable C related-to Entity A,
 * Then Observable C related-to Entity B
 *
 * Pattern:
 * - C related-to A (leftType)
 * - A attributed-to B (rightType)
 * - Result: C related-to B (creationType)
 */
const AttributionObservableRelatedRule = buildRelationToRelationRule(def, {
  leftType: RELATION_RELATED_TO,
  rightType: RELATION_ATTRIBUTED_TO,
  creationType: RELATION_RELATED_TO,
});

export default AttributionObservableRelatedRule;
