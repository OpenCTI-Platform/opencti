import { RELATION_ATTRIBUTED_TO, RELATION_USES } from '../../schema/stixCoreRelationship';

const id = 'attribution_use';
const name = 'Usage via attribution';
const description =
  'If `entity A` **uses** `entity B` and `entity A` is ' +
  '**attributed-to** `entity C`, then `entity C` **uses** `entity B`.';
const scopeFields = [];
const scopeFilters = { types: [RELATION_USES, RELATION_ATTRIBUTED_TO] };

const definition = { id, name, description, scopeFields, scopeFilters };
export default definition;
