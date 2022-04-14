import { RELATION_ATTRIBUTED_TO, RELATION_USES } from '../../schema/stixCoreRelationship';
import type { RuleDefinition, RuleBehavior } from '../../types/rules';

const id = 'attribution_use';
const name = 'Usage via attribution';
const description = 'If **entity A** `uses` **entity B** and **entity A** is '
  + '`attributed-to` **entity C**, then **entity C** `uses` **entity B**.';

// For rescan
const scan = { types: [RELATION_ATTRIBUTED_TO] };

// For live
const filters = { types: [RELATION_USES, RELATION_ATTRIBUTED_TO] };
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
