import { RELATION_PART_OF, RELATION_TARGETS } from '../../schema/stixCoreRelationship';

const id = 'part-of_targets';
const name = 'Targets via Part-Of';
const description =
  'If `entity A` **targets** `entity B` and `entity B` is ' +
  '**part-of** `entity C`, then `entity A` **targets** `entity C`.';
const scopeFields = [];
const scopeFilters = { types: [RELATION_TARGETS, RELATION_PART_OF] };

const definition = { id, name, description, scopeFields, scopeFilters };
export default definition;
