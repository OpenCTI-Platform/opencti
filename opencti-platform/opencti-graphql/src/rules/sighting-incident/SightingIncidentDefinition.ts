import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import type { RuleDefinition } from '../../types/rules';

const id = 'sighting_incident';
const name = 'Raise incident based on sighting';
const description = 'Infer an incident when a sighting is created for a valid indicator.';
const category = 'Alerting';
const display = {
  if: [
    {
      source: 'Indicator A',
      source_color: '#ff9800',
      relation: 'relationship_has',
      target: 'revoked = false',
      target_color: '#4caf50',
    },
    {
      source: 'Indicator A',
      source_color: '#ff9800',
      relation: 'relationship_stix-sighting-relationship',
      target: 'Entity C',
      target_color: '#00bcd4',
    },
  ],
  then: [
    {
      action: 'CREATE',
      source: 'Incident D',
      source_color: '#7e57c2',
    },
    {
      action: 'CREATE',
      relation: 'relationship_related-to',
      source: 'Indicator A',
      source_color: '#ff9800',
      target: 'Incident D',
      target_color: '#7e57c2',
    },
    {
      action: 'CREATE',
      relation: 'relationship_targets',
      source: 'Incident D',
      source_color: '#7e57c2',
      target: 'Entity C',
      target_color: '#00bcd4',
    },
  ],
};

// For rescan
const scan = { types: [STIX_SIGHTING_RELATIONSHIP], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ENTITY_TYPE_IDENTITY] };

// For live
const scopes = [
  {
    filters: { types: [STIX_SIGHTING_RELATIONSHIP], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ENTITY_TYPE_IDENTITY] },
    attributes: [{ name: 'first_seen' }, { name: 'last_seen' }],
  },
  {
    filters: { types: [ENTITY_TYPE_INDICATOR] },
    attributes: [
      { name: 'name' },
      { name: 'pattern' },
      { name: 'object_marking_refs' },
      { name: 'revoked', dependency: true },
    ],
  },
];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
