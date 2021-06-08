/* eslint-disable camelcase */
import buildRelationToRelationRule from '../relation-to-relation/RelationToRelationBuilder';
import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import def from './RelatedToRelatedDefinition';

const RelatedToRelatedRule = buildRelationToRelationRule(
  def.id,
  def.name,
  def.description,
  RELATION_RELATED_TO,
  def.scopeFields,
  def.scopeFilters
);
export default RelatedToRelatedRule;
