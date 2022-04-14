/* eslint-disable camelcase */
import buildRelationToRelationRule from '../relationToRelationBuilder';
import { RELATION_PART_OF } from '../../schema/stixCoreRelationship';
import def from './PartOfPartDefinition';

const PartOfPartRule = buildRelationToRelationRule(def, {
  leftType: RELATION_PART_OF,
  rightType: RELATION_PART_OF,
  creationType: RELATION_PART_OF,
});

export default PartOfPartRule;
