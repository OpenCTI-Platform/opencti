import { ABSTRACT_STIX_CYBER_OBSERVABLE, ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION } from '../../schema/general';
import { ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import type { RuleDefinition } from '../../types/rules';
import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';

const id = 'sighting_indicator';
const name = 'Sightings propagation from indicator';
const description = 'Propagate sightings of indicators to observables.';
const category = 'Alerting';
const display = {
  if: [
    {
      source: 'Indicator A',
      source_color: '#ff9800',
      relation: 'relationship_stix-sighting-relationship',
      target: 'Entity B',
      target_color: '#4caf50',
    },
    {
      source: 'Indicator A',
      source_color: '#ff9800',
      relation: 'relationship_based-on',
      target: 'Observable C',
      target_color: '#00bcd4',
    },
  ],
  then: [
    {
      action: 'CREATE',
      relation: 'relationship_stix-sighting-relationship',
      source: 'Observable C',
      source_color: '#00bcd4',
      target: 'Entity B',
      target_color: '#4caf50',
    },
  ],
};

// For rescan
const scan = { types: [STIX_SIGHTING_RELATIONSHIP], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION] };

// For live
const scopes = [
  {
    filters: { types: [STIX_SIGHTING_RELATIONSHIP], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION] },
    attributes: [],
  },
  {
    filters: { types: [RELATION_BASED_ON], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE] },
    attributes: [],
  },
];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
