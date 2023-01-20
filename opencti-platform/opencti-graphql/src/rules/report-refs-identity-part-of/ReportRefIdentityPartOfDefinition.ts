import { RELATION_PART_OF } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import type { RuleBehavior, RuleDefinition, RuleFilters, RuleScope } from '../../types/rules';

const id = 'report_ref_identity_part_of';
const name = 'Identities propagation in reports';
const description = 'Propagate the parents of an identity in a report.';
const category = 'Report propagation';
const display = {
  if: [
    {
      source: 'Report A',
      source_color: '#ff9800',
      relation: 'relationship_object',
      target: 'Identity B',
      target_color: '#4caf50',
    },
    {
      source: 'Identity B',
      source_color: '#4caf50',
      relation: 'relationship_part-of',
      target: 'Identity C',
      target_color: '#00bcd4',
      identifier: 'Relation D',
      identifier_color: '#673ab7',
    },
  ],
  then: [
    {
      action: 'CREATE',
      relation: 'relationship_object',
      source: 'Report A',
      source_color: '#ff9800',
      target: 'Identity C',
      target_color: '#00bcd4',
    },
    {
      action: 'CREATE',
      relation: 'relationship_object',
      source: 'Report A',
      source_color: '#ff9800',
      target: 'Relation D',
      target_color: '#7e57c2',
    },
  ],
};

// For rescan
const scan: RuleFilters = { types: [ENTITY_TYPE_CONTAINER_REPORT] };

// For live
const scopes: Array<RuleScope> = [
  {
    filters: { types: [ENTITY_TYPE_CONTAINER_REPORT] },
    attributes: [{ name: 'object_refs' }],
  },
  {
    filters: { types: [RELATION_PART_OF], fromTypes: [ENTITY_TYPE_IDENTITY], toTypes: [ENTITY_TYPE_IDENTITY] },
    attributes: [],
  },
];

const behaviors: Array<RuleBehavior> = [];
const definition: RuleDefinition = { id, name, description, scan, scopes, behaviors, category, display };
export default definition;
