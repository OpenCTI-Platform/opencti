/* eslint-disable camelcase */
import { RELATION_ATTRIBUTED_TO, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import def from './AttributionTargetsDefinition';
import buildRelationWithRelationRule from '../relation-with-relation/RelationWithRelationBuilder';

const AttributionTargetsRule = buildRelationWithRelationRule(
  def.id,
  def.name,
  def.description,
  { leftType: RELATION_TARGETS, rightType: RELATION_ATTRIBUTED_TO, creationType: RELATION_TARGETS },
  def.scopeFields,
  def.scopeFilters
);
export default AttributionTargetsRule;
