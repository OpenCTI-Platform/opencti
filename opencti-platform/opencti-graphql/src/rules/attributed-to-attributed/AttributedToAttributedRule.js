/* eslint-disable camelcase */
import buildRelationToRelationRule from '../relation-to-relation/RelationToRelationBuilder';
import { RELATION_ATTRIBUTED_TO } from '../../schema/stixCoreRelationship';
import def from './AttributedToAttributedDefinition';

const AttributedToAttributedRule = buildRelationToRelationRule(
  def.id,
  def.name,
  def.description,
  RELATION_ATTRIBUTED_TO,
  def.scopeFields,
  def.scopeFilters
);
export default AttributedToAttributedRule;
