import { RELATION_LOCATED_AT } from '../../schema/stixCoreRelationship';

const id = 'localization_of_targets';
const name = 'Location of targets';
const description =
  'If `entity A` **targets** `entity B` through `relation X`, and `relation X` is **located-at** `entity C`,' +
  ' then `entity A` **targets**  `entity C`';
const scopeFields = [];
const scopeFilters = { types: [RELATION_LOCATED_AT] };

const definition = { id, name, description, scopeFields, scopeFilters };
export default definition;
