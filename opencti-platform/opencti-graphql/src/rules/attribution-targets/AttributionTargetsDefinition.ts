import { RELATION_ATTRIBUTED_TO, RELATION_TARGETS } from '../../schema/stixCoreRelationship';
import type { RuleDefinition } from '../../types/rules';

const id = 'attribution_targets';
const name = 'Targeting propagation via attribution';
const description = 'Propagate a targeting from a child to its parent via attribution.';
const category = 'Victimology';
const display = {
  if: [
    {
      source: 'Entity A',
      source_color: '#ff9800',
      relation: 'relationship_targets',
      target: 'Entity B',
      target_color: '#4caf50',
    },
    {
      source: 'Entity A',
      source_color: '#ff9800',
      relation: 'relationship_attributed-to',
      target: 'Entity C',
      target_color: '#00bcd4',
    },
  ],
  then: [
    {
      action: 'CREATE',
      relation: 'relationship_targets',
      source: 'Entity C',
      source_color: '#00bcd4',
      target: 'Entity B',
      target_color: '#4caf50',
    },
  ],
};

// For rescan
const scan = { types: [RELATION_ATTRIBUTED_TO] };

// For live
const filters = { types: [RELATION_TARGETS, RELATION_ATTRIBUTED_TO] };
const attributes = [
  { name: 'start_time' },
  { name: 'stop_time' },
  { name: 'confidence' },
  { name: 'object_marking_refs' },
];
const scopes = [{ filters, attributes }];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
