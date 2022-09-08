import { RELATION_PART_OF } from '../../schema/stixCoreRelationship';
import type { RuleDefinition, RuleBehavior } from '../../types/rules';
import { RELATION_PARTICIPATE_TO } from '../../schema/internalRelationship';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../schema/stixDomainObject';

const id = 'participate-to_parts';
const name = 'Participate-to via Part-Of';
const description = 'If **User A** `participate-to` **organization B** and **organization B** is '
  + '`part-of` **organization C**, then **User A** `participate-to` **organization C**.';

// For rescan
const scan = { types: [RELATION_PARTICIPATE_TO], fromTypes: [ENTITY_TYPE_USER], toTypes: [ENTITY_TYPE_IDENTITY_ORGANIZATION] };

// For live
const filterParticipateTo = {
  types: [RELATION_PARTICIPATE_TO],
  fromTypes: [ENTITY_TYPE_USER],
  toTypes: [ENTITY_TYPE_IDENTITY_ORGANIZATION]
};

const filterPartOf = {
  types: [RELATION_PART_OF],
  fromTypes: [ENTITY_TYPE_IDENTITY_ORGANIZATION],
  toTypes: [ENTITY_TYPE_IDENTITY_ORGANIZATION]
};

const behaviors: Array<RuleBehavior> = [];
const scopes = [
  { filters: filterParticipateTo, attributes: [] },
  { filters: filterPartOf, attributes: [] }
];

const definition: RuleDefinition = { id, name, description, scan, scopes, behaviors };
export default definition;
