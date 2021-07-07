import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';

const id = 'observable_related';
const name = 'Related via observable';
const description =
  'If `observable A` is **related-to** `entity B` and `observable A` ' +
  'is **related-to** `entity C`, then `entity B` is **related-to** `entity C`.';
const scopeFields = [];
const scopeFilters = { types: [RELATION_RELATED_TO] };

const definition = { id, name, description, scopeFields, scopeFilters };
export default definition;
