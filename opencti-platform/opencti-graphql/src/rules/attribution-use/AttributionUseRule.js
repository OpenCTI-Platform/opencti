/* eslint-disable camelcase */
import { RELATION_ATTRIBUTED_TO, RELATION_USES } from '../../schema/stixCoreRelationship';
import def from './AttributionUseDefinition';
import buildRelationWithRelationRule from '../relation-with-relation/RelationWithRelationBuilder';

const AttributionUseRule = buildRelationWithRelationRule(
  def.id,
  def.name,
  def.description,
  { leftType: RELATION_USES, rightType: RELATION_ATTRIBUTED_TO, creationType: RELATION_USES },
  def.scopeFields,
  def.scopeFilters
);
export default AttributionUseRule;
