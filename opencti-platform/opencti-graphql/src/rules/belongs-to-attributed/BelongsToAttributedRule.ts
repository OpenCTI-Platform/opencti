/* eslint-disable camelcase */
import buildRelationToRelationRule from '../relationToRelationBuilder';
import { RELATION_ATTRIBUTED_TO, RELATION_BELONGS_TO } from '../../schema/stixCoreRelationship';
import def from './BelongsToAttributedDefinition';

/**
 * Rule: If Entity A belongs to Entity B, If Entity B attributed to Entity C,
 * Then Entity A belongs to Entity C
 *
 * Pattern:
 * - A belongs-to B (leftType)
 * - B attributed-to C (rightType)
 * - Result: A belongs-to C (creationType)
 */
const BelongsToAttributedRule = buildRelationToRelationRule(def, {
  leftType: RELATION_BELONGS_TO,
  rightType: RELATION_ATTRIBUTED_TO,
  creationType: RELATION_BELONGS_TO,
});

export default BelongsToAttributedRule;
