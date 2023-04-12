import { RELATION_ATTRIBUTED_TO } from '../../schema/stixCoreRelationship';
import type { RuleDefinition } from '../../types/rules';

const id = 'attribution_attribution';
const name = 'Attribution propagation';
const description = 'Propagate attributions across parents or children.';
const category = 'Parent-child propagation';
const display = {
  if: [
    {
      source: 'Entity A',
      source_color: '#ff9800',
      relation: 'relationship_attributed-to',
      target: 'Entity B',
      target_color: '#4caf50',
    },
    {
      source: 'Entity B',
      source_color: '#4caf50',
      relation: 'relationship_attributed-to',
      target: 'Entity C',
      target_color: '#00bcd4',
    },
  ],
  then: [
    {
      action: 'CREATE',
      relation: 'relationship_attributed-to',
      source: 'Entity A',
      source_color: '#ff9800',
      target: 'Entity C',
      target_color: '#00bcd4',
    },
  ],
};

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
const scopes = [{ filters, attributes }];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
