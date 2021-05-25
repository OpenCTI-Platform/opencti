/* eslint-disable camelcase */
import { RELATION_RELATED_TO } from '../schema/stixCoreRelationship';
import buildRelationToRelationRule from './RelationToRelationRule';

/*
RelatedRelatedRule: 'This rule can be used to infer the following fact: if an
entity A is related to an entity B and the entity B is related to an entity C, the
entity A is also related to the entity C.'
 */
const RelatedRule = buildRelationToRelationRule('rule_related', RELATION_RELATED_TO);
export default RelatedRule;
