import { RELATION_LOCATED_AT } from '../../schema/stixCoreRelationship';

const id = 'location_location';
const name = 'Location via location';
const description =
  'If `entity A` is **located-at** `entity B` and `entity B` ' +
  'is **located-at** `entity C`, then `entity A` is **located-at** `entity C`.';
const scopeFields = [];
const scopeFilters = { types: [RELATION_LOCATED_AT] };

const definition = { id, name, description, scopeFields, scopeFilters };
export default definition;
