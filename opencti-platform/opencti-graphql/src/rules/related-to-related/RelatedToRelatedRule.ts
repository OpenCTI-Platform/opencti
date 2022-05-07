/* eslint-disable camelcase */
import def from './RelatedToRelatedDefinition';
import buildRelationToRelationRule from '../relationToRelationBuilder';
import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';

const RelatedToRelatedRule = buildRelationToRelationRule(def, {
  leftType: RELATION_RELATED_TO,
  rightType: RELATION_RELATED_TO,
  creationType: RELATION_RELATED_TO,
});

export default RelatedToRelatedRule;
