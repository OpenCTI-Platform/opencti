import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import type { RuleDefinition, RuleFilters, RuleScope } from '../../types/rules';
import { ENTITY_TYPE_INDICATOR } from '../../modules/indicator/indicator-types';

const id = 'report_ref_observable_based_on';
const name = 'Indicators propagation in reports';
const description = 'Propagate indicators of an observable in a report.';
const category = 'Report propagation';
const display = {
  if: [
    {
      source: 'Report A',
      source_color: '#ff9800',
      relation: 'relationship_object',
      target: 'Observable B',
      target_color: '#00bcd4',
    },
    {
      source: 'Indicator C',
      source_color: '#4caf50',
      relation: 'relationship_based-on',
      target: 'Observable B',
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
      target: 'Indicator C',
      target_color: '#4caf50',
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
    filters: { types: [RELATION_BASED_ON], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE] },
    attributes: [],
  },
];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
