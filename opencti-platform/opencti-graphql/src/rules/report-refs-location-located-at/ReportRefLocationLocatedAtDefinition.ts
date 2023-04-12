import { RELATION_LOCATED_AT } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_LOCATION } from '../../schema/general';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import type { RuleDefinition, RuleFilters, RuleScope } from '../../types/rules';

const id = 'report_ref_location_located_at';
const name = 'Locations propagation in reports';
const description = 'Propagate the parents of a location in a report.';
const category = 'Report propagation';
const display = {
  if: [
    {
      source: 'Report A',
      source_color: '#ff9800',
      relation: 'relationship_object',
      target: 'Location B',
      target_color: '#4caf50',
    },
    {
      source: 'Location B',
      source_color: '#4caf50',
      relation: 'relationship_located-at',
      target: 'Location C',
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
      target: 'Location C',
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
const scan: RuleFilters = { types: [RELATION_LOCATED_AT], fromTypes: [ENTITY_TYPE_LOCATION], toTypes: [ENTITY_TYPE_LOCATION] };

// For live
const scopes: Array<RuleScope> = [
  {
    filters: { types: [ENTITY_TYPE_CONTAINER_REPORT] },
    attributes: [{ name: 'object_refs' }],
  },
  {
    filters: { types: [RELATION_LOCATED_AT], fromTypes: [ENTITY_TYPE_LOCATION], toTypes: [ENTITY_TYPE_LOCATION] },
    attributes: [],
  },
];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
