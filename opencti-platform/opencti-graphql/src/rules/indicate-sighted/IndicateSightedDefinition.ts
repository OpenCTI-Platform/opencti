import { RELATION_INDICATES } from '../../schema/stixCoreRelationship';
import type { RuleBehavior, RuleDefinition } from '../../types/rules';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import {
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_MALWARE
} from '../../schema/stixDomainObject';

const id = 'indicate_sighted';
const name = 'Targets via sighting';
const description = 'If **indicator A** `sighted` **organization B** and **indicator A** '
  + '`indicates` **Malware C**, then **Malware C** `targets` **organization B**.';

// For rescan
const scan = { types: [STIX_SIGHTING_RELATIONSHIP], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ENTITY_TYPE_IDENTITY_ORGANIZATION] };

// For live
const filters = {
  types: [STIX_SIGHTING_RELATIONSHIP, RELATION_INDICATES],
  fromTypes: [ENTITY_TYPE_INDICATOR],
  toTypes: [ENTITY_TYPE_IDENTITY_ORGANIZATION, ENTITY_TYPE_MALWARE]
};
const attributes = [
  { name: 'start_time' },
  { name: 'stop_time' },
  { name: 'confidence' },
  { name: 'object_marking_refs' },
];
const behaviors: Array<RuleBehavior> = [];
const scopes = [{ filters, attributes }];

const definition: RuleDefinition = { id, name, description, scan, scopes, behaviors };
export default definition;
