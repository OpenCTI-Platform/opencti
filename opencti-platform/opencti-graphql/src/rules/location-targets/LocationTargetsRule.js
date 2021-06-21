/* eslint-disable camelcase */
import { RELATION_LOCATED_AT, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import def from './LocationTargetsDefinition';
import buildRelationToRelationRule from '../relation-to-relation/RelationToRelationBuilder';

const LocationTargetsRule = buildRelationToRelationRule(
  def.id,
  def.name,
  def.description,
  { leftType: RELATION_TARGETS, rightType: RELATION_LOCATED_AT, creationType: RELATION_TARGETS },
  def.scopeFields,
  def.scopeFilters
);
export default LocationTargetsRule;
