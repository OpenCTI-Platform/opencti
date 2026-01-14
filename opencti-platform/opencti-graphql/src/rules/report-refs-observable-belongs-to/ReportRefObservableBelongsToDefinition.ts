import { RELATION_BELONGS_TO } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import type { RuleDefinition, RuleFilters, RuleScope } from '../../types/rules';

const id = 'report_ref_observable_belongs_to';
const name = 'Observables propagation in reports via belongs-to';
const description = 'Propagate observables that an observable belongs to in a report.';
const category = 'Report propagation';
const display = {
  if: [
    {
      source: 'Report A',
      source_color: '#ff9800',
      relation: 'relationship_object',
      target: 'Observable B',
      target_color: '#4caf50',
    },
    {
      source: 'Observable B',
      source_color: '#4caf50',
      relation: 'relationship_belongs-to',
      target: 'Observable C',
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
      target: 'Observable C',
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
    filters: { types: [RELATION_BELONGS_TO], fromTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE], toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE] },
    attributes: [],
  },
];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
