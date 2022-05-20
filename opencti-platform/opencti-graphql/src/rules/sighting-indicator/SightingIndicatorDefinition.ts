import { ABSTRACT_STIX_CYBER_OBSERVABLE, ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION } from '../../schema/general';
import { ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import type { RuleDefinition, RuleBehavior } from '../../types/rules';
import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';

const id = 'sighting_indicator';
const name = 'Observable sighting via Indicator';
const description = 'If **indicator A** is `sighted` in **identity/location B** and '
    + '**indicator A** `based on` **observable C**, '
    + 'then create **observable C** `sighted` in **identity/location B**.';

// For rescan
const scan = { types: [STIX_SIGHTING_RELATIONSHIP], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION] };

// For live
const behaviors: Array<RuleBehavior> = [];
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

const definition: RuleDefinition = { id, name, description, scan, scopes, behaviors };
export default definition;
