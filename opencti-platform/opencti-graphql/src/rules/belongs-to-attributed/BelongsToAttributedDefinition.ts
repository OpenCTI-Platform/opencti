import { RELATION_ATTRIBUTED_TO, RELATION_BELONGS_TO } from '../../schema/stixCoreRelationship';
import type { RuleDefinition } from '../../types/rules';

const id = 'belongs_to_attributed';
const name = 'Belongs-to propagation via attribution';
const description = 'If an entity belongs to another entity and that entity is attributed to a third entity, then the first entity also belongs to the third entity.';
const category = 'Parent-child propagation';
const display = {
  if: [
    {
      source: 'Entity A',
      source_color: '#ff9800',
      relation: 'relationship_belongs-to',
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
      relation: 'relationship_belongs-to',
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
const filters = { types: [RELATION_BELONGS_TO, RELATION_ATTRIBUTED_TO] };
const attributes = [
  { name: 'start_time' },
  { name: 'stop_time' },
  { name: 'confidence' },
  { name: 'object_marking_refs' },
];
const scopes = [{ filters, attributes }];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
