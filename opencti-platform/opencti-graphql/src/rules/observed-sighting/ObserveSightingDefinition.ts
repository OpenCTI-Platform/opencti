import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA, ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';
import { RULES_ATTRIBUTES_BEHAVIOR } from '../rules';
import type { RuleDefinition, RuleFilters, RuleScope } from '../../types/rules';

const id = 'observe_sighting';
const name = 'Sightings of observables via observed data';
const description = 'Infer sightings based on observed data and indicators.';
const behaviors = [{ ruleId: id, attribute: 'attribute_count', operation: RULES_ATTRIBUTES_BEHAVIOR.OPERATIONS.SUM }];
const category = 'Alerting';
const display = {
  if: [
    {
      source: 'Observed Data A',
      source_color: '#ff9800',
      relation: 'relationship_created-by',
      target: 'Identity B',
      target_color: '#7e57c2',
    },
    {
      source: 'Observed Data A',
      source_color: '#ff9800',
      relation: 'relationship_object',
      target: 'Observable C',
      target_color: '#4caf50',
    },
    {
      source: 'Indicator D',
      source_color: '#00bcd4',
      relation: 'relationship_based-on',
      target: 'Observable C',
      target_color: '#4caf50',
    },
  ],
  then: [
    {
      action: 'CREATE',
      relation: 'relationship_stix-sighting-relationship',
      source: 'Indicator D',
      source_color: '#00bcd4',
      target: 'Identity B',
      target_color: '#7e57c2',
    },
  ],
};

// For rescan
const scan: RuleFilters = { types: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA] };

// For live
const scopes: Array<RuleScope> = [
  {
    filters: {
      types: [RELATION_BASED_ON],
      fromTypes: [ENTITY_TYPE_INDICATOR],
      toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE],
    },
    attributes: [],
  },
  {
    filters: { types: [ENTITY_TYPE_INDICATOR] },
    attributes: [],
  },
  {
    filters: { types: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA] },
    attributes: [
      { name: 'created_by_ref', dependency: true },
      { name: 'first_observed' },
      { name: 'last_observed' },
      { name: 'number_observed' },
      { name: 'confidence' },
      { name: 'object_marking_refs' },
    ],
  },
];

const definition: RuleDefinition = { id, name, description, scan, scopes, behaviors, category, display };
export default definition;
