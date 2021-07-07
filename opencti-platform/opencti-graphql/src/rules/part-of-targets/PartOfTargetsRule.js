/* eslint-disable camelcase */
import { RELATION_PART_OF, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import def from './PartOfTargetsDefinition';
import buildRelationToRelationRule from '../relation-to-relation/RelationToRelationBuilder';

const PartOfTargetsRule = buildRelationToRelationRule(
  def.id,
  def.name,
  def.description,
  { leftType: RELATION_TARGETS, rightType: RELATION_PART_OF, creationType: RELATION_TARGETS },
  def.scopeFields,
  def.scopeFilters
);
export default PartOfTargetsRule;
