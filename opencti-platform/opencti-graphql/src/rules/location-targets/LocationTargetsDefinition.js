import { RELATION_LOCATED_AT, RELATION_TARGETS } from '../../schema/stixCoreRelationship';

const id = 'location_targets';
const name = 'Targets via location';
const description =
  'If `entity A` **targets** `entity B` and `entity B` is ' +
  '**located-at** `entity C`, then `entity A` **targets** `entity C`.';
const scopeFields = [];
const scopeFilters = { types: [RELATION_TARGETS, RELATION_LOCATED_AT] };

const definition = { id, name, description, scopeFields, scopeFilters };
export default definition;
