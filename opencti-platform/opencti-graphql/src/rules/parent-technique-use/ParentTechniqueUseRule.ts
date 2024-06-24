/* eslint-disable camelcase */
import { RELATION_SUBTECHNIQUE_OF, RELATION_USES } from '../../schema/stixCoreRelationship';
import def from './ParentTechniqueUseDefinition';
import buildRelationToRelationRule from '../relationToRelationBuilder';

const ParentTechniqueUseRule = buildRelationToRelationRule(def, {
  leftType: RELATION_USES,
  rightType: RELATION_SUBTECHNIQUE_OF,
  creationType: RELATION_USES,
});

export default ParentTechniqueUseRule;
