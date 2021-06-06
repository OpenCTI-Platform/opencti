/* eslint-disable camelcase */
import buildRelationToRelationRule from './builder/RelationToRelationBuilder';
import { RELATION_RELATED_TO } from '../schema/stixCoreRelationship';

// region configuration
const id = 'related_related';
const name = 'Related testing';
const description = 'Test related rule';
const type = RELATION_RELATED_TO;
const scopeFields = [];
const scopeFilters = { types: [RELATION_RELATED_TO] };
// endregion

const RelatedToRelated = buildRelationToRelationRule(id, name, description, type, scopeFields, scopeFilters);
export default RelatedToRelated;
