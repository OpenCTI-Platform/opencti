import { RELATION_ATTRIBUTED_TO, RELATION_USES } from '../../schema/stixCoreRelationship';

const id = 'attribution_use';
const name = 'Attribution uses';
const description =
  'this rule can be used to infer the following fact: if an entity A uses an object B and the entity A ' +
  'is attributed to an entity C, the entity C is also using the object B.';
const scopeFields = [];
const scopeFilters = { types: [RELATION_USES, RELATION_ATTRIBUTED_TO] };

const definition = { id, name, description, scopeFields, scopeFilters };
export default definition;
