import { RELATION_CONSISTS_OF, RELATION_USES } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import { ENTITY_TYPE_INFRASTRUCTURE } from '../../schema/stixDomainObject';
import type { RuleDefinition } from '../../types/rules';

const id = 'infrastructure_observable_related';
const name = 'Observable related to entity via infrastructure';
const description = 'If an entity uses an infrastructure and the infrastructure consists of an observable, then the observable is related to the entity.';
const category = 'Correlation';
const display = {
  if: [
    {
      source: 'Entity A',
      source_color: '#ff9800',
      relation: 'relationship_uses',
      target: 'Infrastructure B',
      target_color: '#4caf50',
    },
    {
      source: 'Infrastructure B',
      source_color: '#4caf50',
      relation: 'relationship_consists-of',
      target: 'Observable C',
      target_color: '#00bcd4',
    },
  ],
  then: [
    {
      action: 'CREATE',
      relation: 'relationship_related-to',
      source: 'Observable C',
      source_color: '#00bcd4',
      target: 'Entity A',
      target_color: '#ff9800',
    },
  ],
};

// For rescan
const scan = {
  types: [RELATION_CONSISTS_OF],
  fromTypes: [ENTITY_TYPE_INFRASTRUCTURE],
  toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE],
};

// For live
const filters = { types: [RELATION_USES, RELATION_CONSISTS_OF] };
const attributes = [
  { name: 'start_time' },
  { name: 'stop_time' },
  { name: 'confidence' },
  { name: 'object_marking_refs' },
];
const scopes = [{ filters, attributes }];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
