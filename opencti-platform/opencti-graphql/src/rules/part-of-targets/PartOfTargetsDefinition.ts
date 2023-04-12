import { RELATION_PART_OF, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import type { RuleDefinition } from '../../types/rules';

const id = 'part-of_targets';
const name = 'Targeting propagation via belonging';
const description = 'Propagate a targeting from a child to its parent via belonging.';
const category = 'Victimology';
const display = {
  if: [
    {
      source: 'Entity A',
      source_color: '#ff9800',
      relation: 'relationship_targets',
      target: 'Identity B',
      target_color: '#4caf50',
    },
    {
      source: 'Identity B',
      source_color: '#4caf50',
      relation: 'relationship_part-of',
      target: 'Identity C',
      target_color: '#00bcd4',
    },
  ],
  then: [
    {
      action: 'CREATE',
      relation: 'relationship_targets',
      source: 'Entity A',
      source_color: '#ff9800',
      target: 'Identity C',
      target_color: '#00bcd4',
    },
  ],
};

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
const scopes = [{ filters, attributes }];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
