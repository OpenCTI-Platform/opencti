import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INDICATOR } from '../../schema/stixDomainObject';
import type { RuleBehavior, RuleDefinition, RuleFilters, RuleScope } from '../../types/rules';

const id = 'report_ref_indicator_based_on';
const name = 'Report objects indicators based on';
const description = 'If **report A** have `object_ref` **indicator B** and **indicator B** '
  + 'is `based-on (C)` **observable D**, then **report A** have `object_ref` **observable D** + **based-on (C)**.';

// For rescan
const scan: RuleFilters = { types: [RELATION_BASED_ON], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE] };

// For live
const scopes: Array<RuleScope> = [
  {
    filters: { types: [ENTITY_TYPE_CONTAINER_REPORT] },
    attributes: [{ name: 'object_refs' }],
  },
  {
    filters: { types: [RELATION_BASED_ON], fromTypes: [ENTITY_TYPE_INDICATOR], toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE] },
    attributes: [],
  },
];

const behaviors: Array<RuleBehavior> = [];
const definition: RuleDefinition = { id, name, description, scan, scopes, behaviors };
export default definition;
