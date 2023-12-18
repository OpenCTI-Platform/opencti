/* eslint-disable camelcase */
import { RELATION_PART_OF, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import def from './PartOfTargetsDefinition';
import buildRelationToRelationRule from '../relationToRelationBuilder';

const PartOfTargetsRule = buildRelationToRelationRule(def, {
  leftType: RELATION_TARGETS,
  rightType: RELATION_PART_OF,
  creationType: RELATION_TARGETS,
});

export default PartOfTargetsRule;
