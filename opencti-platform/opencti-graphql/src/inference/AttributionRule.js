/* eslint-disable camelcase */
import { RELATION_ATTRIBUTED_TO } from '../schema/stixCoreRelationship';
import buildRelationToRelationRule from './RelationToRelationRule';

/*
AttributionAttributionRule: 'This rule can be used to infer the following fact: if an
entity A is attributed to an entity B and the entity B is attributed to an entity C, the
entity A is also attributed to the entity C.'
 */
const AttributionRule = buildRelationToRelationRule('rule_attribution', RELATION_ATTRIBUTED_TO);
export default AttributionRule;
