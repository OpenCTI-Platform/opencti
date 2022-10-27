import { RELATION_PART_OF } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import type { RuleDefinition, RuleBehavior, RuleFilters, RuleScope } from '../../types/rules';

const id = 'report_ref_identity_part_of';
const name = 'Report objects identities part of';
const description = 'If **report A** have `object_ref` **identity B** and **identity B** '
  + 'is `part-of (C)` **identity D**, then **report A** have `object_ref` **identity D** + **part-of (C)**.';

// For rescan
const scan: RuleFilters = { types: [RELATION_PART_OF], fromTypes: [ENTITY_TYPE_IDENTITY], toTypes: [ENTITY_TYPE_IDENTITY] };

// For live
const scopes: Array<RuleScope> = [
  {
    filters: { types: [ENTITY_TYPE_CONTAINER_REPORT] },
    attributes: [{ name: 'object_refs' }],
  },
  {
    filters: { types: [RELATION_PART_OF], fromTypes: [ENTITY_TYPE_IDENTITY], toTypes: [ENTITY_TYPE_IDENTITY] },
    attributes: [],
  },
];

const behaviors: Array<RuleBehavior> = [];
const definition: RuleDefinition = { id, name, description, scan, scopes, behaviors };
export default definition;
