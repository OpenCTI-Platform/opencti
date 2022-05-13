import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import type { RuleDefinition, RuleBehavior } from '../../types/rules';

const id = 'sighting_incident';
const name = 'Sighting incidents';
const description = 'If **indicator A** has `revoked` **false** and **indicator A** is `sighted` in '
  + '**identity B**, then create **Incident C** `related-to` **indicator A** and '
  + '`targets` **identity B**.';

// For rescan
const scan = { types: [STIX_SIGHTING_RELATIONSHIP], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ENTITY_TYPE_IDENTITY] };

// For live
const behaviors: Array<RuleBehavior> = [];
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

const definition: RuleDefinition = { id, name, description, scan, scopes, behaviors };
export default definition;
