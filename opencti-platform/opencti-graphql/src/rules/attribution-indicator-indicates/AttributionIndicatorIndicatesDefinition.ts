import { RELATION_ATTRIBUTED_TO, RELATION_INDICATES } from '../../schema/stixCoreRelationship';
import type { RuleDefinition } from '../../types/rules';

const id = 'attribution_indicator_indicates';
const name = 'Indicator propagation via attribution';
const description = 'If an entity is attributed to another entity and an indicator indicates the first entity, then the indicator also indicates the second entity.';
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
      source: 'Indicator C',
      source_color: '#00bcd4',
      relation: 'relationship_indicates',
      target: 'Entity A',
      target_color: '#ff9800',
    },
  ],
  then: [
    {
      action: 'CREATE',
      relation: 'relationship_indicates',
      source: 'Indicator C',
      source_color: '#00bcd4',
      target: 'Entity B',
      target_color: '#4caf50',
    },
  ],
};

// For rescan
const scan = { types: [RELATION_ATTRIBUTED_TO] };

// For live
const filters = { types: [RELATION_INDICATES, RELATION_ATTRIBUTED_TO] };
const attributes = [
  { name: 'start_time' },
  { name: 'stop_time' },
  { name: 'confidence' },
  { name: 'object_marking_refs' },
];
const scopes = [{ filters, attributes }];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
