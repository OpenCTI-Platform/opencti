import { RELATION_SUBTECHNIQUE_OF, RELATION_USES } from '../../schema/stixCoreRelationship';
import type { RuleDefinition } from '../../types/rules';

const id = 'parent_technique_use';
const name = 'Usage propagation of parent techniques';
const description = 'Propagate a usage from a subtechnique to its parent.';
const category = 'Parent-child propagation';
const display = {
  if: [
    {
      source: 'Entity A',
      source_color: '#ff9800',
      relation: 'relationship_uses',
      target: 'Entity B',
      target_color: '#4caf50',
    },
    {
      source: 'Entity B',
      source_color: '#4caf50',
      relation: 'relationship_subtechnique-of',
      target: 'Entity C',
      target_color: '#00bcd4',
    },
  ],
  then: [
    {
      action: 'CREATE',
      relation: 'relationship_uses',
      source: 'Entity A',
      source_color: '#ff9800',
      target: 'Entity C',
      target_color: '#00bcd4',
    },
  ],
};

// For rescan
const scan = { types: [RELATION_USES] };

// For live
const filters = { types: [RELATION_USES, RELATION_SUBTECHNIQUE_OF] };
const attributes = [
  { name: 'start_time' },
  { name: 'stop_time' },
  { name: 'confidence' },
  { name: 'object_marking_refs' },
];
const scopes = [{ filters, attributes }];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
