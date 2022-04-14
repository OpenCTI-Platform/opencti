import { RELATION_PART_OF, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import type { RuleDefinition, RuleBehavior } from '../../types/rules';

const id = 'part-of_targets';
const name = 'Targets via Part-Of';
const description = 'If **entity A** `targets` **entity B** and **entity B** is '
  + '`part-of` **entity C**, then **entity A** `targets` **entity C**.';

// For rescan
const scan = { types: [RELATION_TARGETS] };

// For live
const filters = { types: [RELATION_TARGETS, RELATION_PART_OF] };
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
