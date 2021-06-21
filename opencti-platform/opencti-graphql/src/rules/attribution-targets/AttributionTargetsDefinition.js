import { RELATION_ATTRIBUTED_TO, RELATION_TARGETS } from '../../schema/stixCoreRelationship';

const id = 'attribution_targets';
const name = 'Targets via attribution';
const description =
  'If `entity A` **targets** `entity B` and `entity A` is ' +
  '**attributed-to** `entity C`, then `entity C` **targets** `entity B`.';
const scopeFields = [];
const scopeFilters = { types: [RELATION_TARGETS, RELATION_ATTRIBUTED_TO] };

const definition = { id, name, description, scopeFields, scopeFilters };
export default definition;
