import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';

const id = 'observable_related';
const name = 'Observable connection';
const description =
  'This rule will infer the following fact: if an Observable A is related to an entity B and the Observable' +
  ' A is related to an entity C, the entity B is also related to the entity C.';
const scopeFields = [];
const scopeFilters = { types: [RELATION_RELATED_TO] };

const definition = { id, name, description, scopeFields, scopeFilters };
export default definition;
