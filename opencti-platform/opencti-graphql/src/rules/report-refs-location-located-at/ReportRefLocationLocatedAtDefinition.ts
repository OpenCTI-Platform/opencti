import { RELATION_LOCATED_AT } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_LOCATION } from '../../schema/general';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import type { RuleBehavior, RuleDefinition, RuleFilters, RuleScope } from '../../types/rules';

const id = 'report_ref_location_located_at';
const name = 'Report objects location located at';
const description = 'If **report A** have `object_ref` **location B** and **location B** '
  + 'is `located-at (C)` **location D**, then **report A** have `object_ref` **location D** + **located-at (C)**.';

// For rescan
const scan: RuleFilters = { types: [RELATION_LOCATED_AT], fromTypes: [ENTITY_TYPE_LOCATION], toTypes: [ENTITY_TYPE_LOCATION] };

// For live
const scopes: Array<RuleScope> = [
  {
    filters: { types: [ENTITY_TYPE_CONTAINER_REPORT] },
    attributes: [{ name: 'object_refs' }],
  },
  {
    filters: { types: [RELATION_LOCATED_AT], fromTypes: [ENTITY_TYPE_LOCATION], toTypes: [ENTITY_TYPE_LOCATION] },
    attributes: [],
  },
];

const behaviors: Array<RuleBehavior> = [];
const definition: RuleDefinition = { id, name, description, scan, scopes, behaviors };
export default definition;
