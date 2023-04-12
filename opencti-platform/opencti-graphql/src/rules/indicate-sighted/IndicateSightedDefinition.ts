import { RELATION_INDICATES } from '../../schema/stixCoreRelationship';
import type { RuleDefinition } from '../../types/rules';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import {
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION } from '../../schema/general';

const id = 'indicate_sighted';
const name = 'Inference of targeting via a sighting';
const description = 'Infer the targeting of an entity through a sighting of a specific indicator.';
const category = 'Victimology';
const display = {
  if: [
    {
      source: 'Indicator A',
      source_color: '#ff9800',
      relation: 'relationship_indicates',
      target: 'Entity B',
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
      relation: 'relationship_targets',
      source: 'Entity B',
      source_color: '#4caf50',
      target: 'Entity C',
      target_color: '#00bcd4',
    },
  ],
};

// For rescan
const scan = { types: [STIX_SIGHTING_RELATIONSHIP], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION] };

// For live
const filtersSighting = { types: [STIX_SIGHTING_RELATIONSHIP], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION] };
const filtersIndicates = {
  types: [RELATION_INDICATES],
  fromTypes: [ENTITY_TYPE_INDICATOR],
  toTypes: [ENTITY_TYPE_MALWARE, ENTITY_TYPE_THREAT_ACTOR, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INCIDENT]
};
const scopes = [
  { filters: filtersSighting, attributes: [] },
  { filters: filtersIndicates, attributes: [] }
];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
