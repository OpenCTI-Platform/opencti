import { RELATION_LOCATED_AT } from '../../schema/stixCoreRelationship';
import type { RuleDefinition } from '../../types/rules';

const id = 'location_location';
const name = 'Location propagation';
const description = 'Propagate locations across parents or children.';
const category = 'Parent-child propagation';
const display = {
  if: [
    {
      source: 'Location A',
      source_color: '#ff9800',
      relation: 'relationship_located-at',
      target: 'Location B',
      target_color: '#4caf50',
    },
    {
      source: 'Location B',
      source_color: '#4caf50',
      relation: 'relationship_located-at',
      target: 'Location C',
      target_color: '#00bcd4',
    },
  ],
  then: [
    {
      action: 'CREATE',
      relation: 'relationship_located-at',
      source: 'Location A',
      source_color: '#ff9800',
      target: 'Location C',
      target_color: '#00bcd4',
    },
  ],
};

// For rescan
const scan = { types: [RELATION_LOCATED_AT] };

// For live
const filters = { types: [RELATION_LOCATED_AT] };
const attributes = [
  { name: 'start_time' },
  { name: 'stop_time' },
  { name: 'confidence' },
  { name: 'object_marking_refs' },
];
const scopes = [{ filters, attributes }];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
