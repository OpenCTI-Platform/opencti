import { RELATION_ATTRIBUTED_TO } from '../../schema/stixCoreRelationship';

const id = 'attribution_attribution';
const name = 'Attribution via attribution';
const description =
  'If `entity A` is **attributed-to** `entity B` and `entity B` ' +
  'is **attributed-to** `entity C`, then `entity A` is **attributed-to** `entity C`.';
const scopeFields = [];
const scopeFilters = { types: [RELATION_ATTRIBUTED_TO] };

const definition = { id, name, description, scopeFields, scopeFilters };
export default definition;
