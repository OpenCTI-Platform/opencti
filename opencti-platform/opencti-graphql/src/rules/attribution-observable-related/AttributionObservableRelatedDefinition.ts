import { RELATION_ATTRIBUTED_TO, RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import type { RuleDefinition } from '../../types/rules';

const id = 'attribution_observable_related';
const name = 'Observable relation propagation via attribution';
const description = 'If an entity is attributed to another entity and an observable is related to the first entity, then the observable is also related to the second entity.';
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
      source: 'Observable C',
      source_color: '#00bcd4',
      relation: 'relationship_related-to',
      target: 'Entity A',
      target_color: '#ff9800',
    },
  ],
  then: [
    {
      action: 'CREATE',
      relation: 'relationship_related-to',
      source: 'Observable C',
      source_color: '#00bcd4',
      target: 'Entity B',
      target_color: '#4caf50',
    },
  ],
};

// For rescan
const scan = { types: [RELATION_ATTRIBUTED_TO] };

// For live
const filters = { types: [RELATION_RELATED_TO, RELATION_ATTRIBUTED_TO] };
const attributes = [
  { name: 'start_time' },
  { name: 'stop_time' },
  { name: 'confidence' },
  { name: 'object_marking_refs' },
];
const scopes = [{ filters, attributes }];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
