import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import { RELATION_OBJECT } from '../../schema/stixMetaRelationship';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA, ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';
import { RULES_ATTRIBUTES_BEHAVIOR } from '../rules';
import type { RuleDefinition, RuleFilters, RuleScope } from '../../types/rules';

const id = 'observe_sighting';
const name = 'Sighting observable';
const description = 'If **observed-data A** (`created-by` **identity X**) have `object` **observable B** and **indicator C** '
  + 'is `based-on` **observable B**, then **indicator C** is `sighted` in **identity X**.';
const behaviors = [{ ruleId: id, attribute: 'attribute_count', operation: RULES_ATTRIBUTES_BEHAVIOR.OPERATIONS.SUM }];

// For rescan
const scan: RuleFilters = {
  types: [RELATION_OBJECT],
  fromTypes: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA],
  toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE],
};

// For live
const scopes: Array<RuleScope> = [
  {
    filters: {
      types: [RELATION_OBJECT],
      fromTypes: [ENTITY_TYPE_CONTAINER_OBSERVED_DATA],
      toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE],
    },
    attributes: [],
  },
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

const definition: RuleDefinition = { id, name, description, scan, scopes, behaviors };
export default definition;
