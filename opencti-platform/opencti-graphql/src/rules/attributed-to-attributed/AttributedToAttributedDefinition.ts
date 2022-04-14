import { RELATION_ATTRIBUTED_TO } from '../../schema/stixCoreRelationship';
import type { RuleBehavior, RuleDefinition } from '../../types/rules';

const id = 'attribution_attribution';
const name = 'Attribution via attribution';
const description = 'If **entity A** is `attributed-to` **entity B** and **entity B** '
  + 'is `attributed-to` **entity C**, then **entity A** is `attributed-to` **entity C**.';

// For rescan
const scan = { types: [RELATION_ATTRIBUTED_TO] };

// For live
const filters = { types: [RELATION_ATTRIBUTED_TO] };
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
