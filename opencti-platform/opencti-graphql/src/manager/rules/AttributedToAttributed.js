/* eslint-disable camelcase */
import buildRelationToRelationRule from './builder/RelationToRelationBuilder';
import { RELATION_ATTRIBUTED_TO } from '../../schema/stixCoreRelationship';

// region configuration
const id = 'attribution_attribution';
const name = 'Attribution relation';
const description =
  'This rule will infer the following fact: if an entity A is attributed to an' +
  ' entity B and the entity B is attributed to an entity C, the entity A is also attributed to the entity C.';
const type = RELATION_ATTRIBUTED_TO;
const scopeFields = [];
const scopeFilters = { types: [RELATION_ATTRIBUTED_TO] };
// endregion

const AttributedToAttributed = buildRelationToRelationRule(id, name, description, type, scopeFields, scopeFilters);
export default AttributedToAttributed;
