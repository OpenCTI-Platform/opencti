/* eslint-disable camelcase */
import buildRelationToRelationRule from './RuleRelationInference';
import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';

const name = 'related_related';
const description = 'Test related rule';
const type = RELATION_RELATED_TO;
const scopeFilters = { types: [RELATION_RELATED_TO] };
const RuleRelatedInference = buildRelationToRelationRule(name, description, type, '*', scopeFilters);
export default RuleRelatedInference;
