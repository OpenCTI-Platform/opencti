/* eslint-disable camelcase */
import buildRelationToRelationRule from '../relation-to-relation/RelationToRelationBuilder';
import { RELATION_LOCATED_AT } from '../../schema/stixCoreRelationship';
import def from './LocatedAtLocatedDefinition';

const LocatedAtLocatedRule = buildRelationToRelationRule(
  def.id,
  def.name,
  def.description,
  { leftType: RELATION_LOCATED_AT, rightType: RELATION_LOCATED_AT, creationType: RELATION_LOCATED_AT },
  def.scopeFields,
  def.scopeFilters
);
export default LocatedAtLocatedRule;
