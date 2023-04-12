import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import type { RuleDefinition } from '../../types/rules';

const id = 'related_related';
const name = 'Relation propagation testing rule';
const description = 'Propagate related objects over the whole graph. Testing only.';
const category = 'Testing';
const display = {
  if: [
    {
      source: 'Entity A',
      source_color: '#ff9800',
      relation: 'relationship_related-to',
      target: 'Entity B',
      target_color: '#4caf50',
    },
    {
      source: 'Entity B',
      source_color: '#4caf50',
      relation: 'relationship_related-to',
      target: 'Entity C',
      target_color: '#00bcd4',
    },
  ],
  then: [
    {
      action: 'CREATE',
      relation: 'relationship_related-to',
      source: 'Entity A',
      source_color: '#ff9800',
      target: 'Entity C',
      target_color: '#00bcd4',
    },
  ],
};

// For rescan
const scan = { types: [RELATION_RELATED_TO] };

// For live
const filters = { types: [RELATION_RELATED_TO] };
const attributes = [
  { name: 'start_time' },
  { name: 'stop_time' },
  { name: 'confidence' },
  { name: 'object_marking_refs' },
];
const scopes = [{ filters, attributes }];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
