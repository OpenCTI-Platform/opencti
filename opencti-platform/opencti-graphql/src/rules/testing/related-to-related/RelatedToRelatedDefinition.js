import { RELATION_RELATED_TO } from '../../../schema/stixCoreRelationship';

const id = 'related_related';
const name = 'Related testing';
const description = 'Test related rule';
const scopeFields = [];
const scopeFilters = { types: [RELATION_RELATED_TO] };

const definition = { id, name, description, scopeFields, scopeFilters };
export default definition;
