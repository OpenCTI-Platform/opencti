import { RELATION_INDICATES } from '../../schema/stixCoreRelationship';
import type { RuleBehavior, RuleDefinition } from '../../types/rules';
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
const name = 'Targets via sighting';
const description = 'If **indicator A** `sighted` **identity/location B** and **indicator A** '
  + '`indicates` **malware/threat actor/intrusion set/campaign/incident C**, then **malware/threat... C** `targets` **identity/location B**.';

// For rescan
const scan = { types: [STIX_SIGHTING_RELATIONSHIP], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION] };

// For live
const filtersSighting = { types: [STIX_SIGHTING_RELATIONSHIP], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION] };
const filtersIndicates = {
  types: [RELATION_INDICATES],
  fromTypes: [ENTITY_TYPE_INDICATOR],
  toTypes: [ENTITY_TYPE_MALWARE, ENTITY_TYPE_THREAT_ACTOR, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INCIDENT]
};
const behaviors: Array<RuleBehavior> = [];
const scopes = [
  { filters: filtersSighting, attributes: [] },
  { filters: filtersIndicates, attributes: [] }
];

const definition: RuleDefinition = { id, name, description, scan, scopes, behaviors };
export default definition;
