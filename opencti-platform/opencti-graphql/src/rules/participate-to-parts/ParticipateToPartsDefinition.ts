import { RELATION_PART_OF } from '../../schema/stixCoreRelationship';
import type { RuleDefinition } from '../../types/rules';
import { RELATION_PARTICIPATE_TO } from '../../schema/internalRelationship';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../modules/organization/organization-types';

const id = 'participate-to_parts';
const name = 'Organization propagation via participation';
const description = 'Propagate an organization from a child to its parent via participation.';
const category = 'Parent-child propagation';
const display = {
  if: [
    {
      source: 'User A',
      source_color: '#ff9800',
      relation: 'relationship_participate-to',
      target: 'Organization B',
      target_color: '#4caf50',
    },
    {
      source: 'Organization B',
      source_color: '#4caf50',
      relation: 'relationship_part-of',
      target: 'Organization C',
      target_color: '#00bcd4',
    },
  ],
  then: [
    {
      action: 'CREATE',
      relation: 'relationship_participate-to',
      source: 'User A',
      source_color: '#ff9800',
      target: 'organization C',
      target_color: '#00bcd4',
    },
  ],
};

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

const scopes = [
  { filters: filterParticipateTo, attributes: [] },
  { filters: filterPartOf, attributes: [] }
];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
