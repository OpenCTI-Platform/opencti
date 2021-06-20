/* eslint-disable camelcase */
import { RELATION_LOCATED_AT, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import def from './LocationTargetsDefinition';
import buildRelationWithRelationRule from '../relation-with-relation/RelationWithRelationBuilder';

const LocationTargetsRule = buildRelationWithRelationRule(
  def.id,
  def.name,
  def.description,
  { leftType: RELATION_TARGETS, rightType: RELATION_LOCATED_AT, creationType: RELATION_TARGETS },
  def.scopeFields,
  def.scopeFilters
);
export default LocationTargetsRule;
