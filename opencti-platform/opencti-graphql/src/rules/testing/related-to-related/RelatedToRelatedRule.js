/* eslint-disable camelcase */
import buildRelationToRelationRule from '../../relation-to-relation/RelationToRelationBuilder';
import { RELATION_RELATED_TO } from '../../../schema/stixCoreRelationship';
import def from './RelatedToRelatedDefinition';

const RelatedToRelatedRule = buildRelationToRelationRule(
  def.id,
  def.name,
  def.description,
  { leftType: RELATION_RELATED_TO, rightType: RELATION_RELATED_TO, creationType: RELATION_RELATED_TO },
  def.scopeFields,
  def.scopeFilters
);
export default RelatedToRelatedRule;
