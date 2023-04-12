import { RELATION_LOCATED_AT } from '../../schema/stixCoreRelationship';
import type { RuleDefinition } from '../../types/rules';

const id = 'localization_of_targets';
const name = 'Targeting propagation when located';
const description = 'Propagate targeting when the target relationship is located somewhere.';
const category = 'Victimology';
const display = {
  if: [
    {
      source: 'Entity A',
      source_color: '#ff9800',
      relation: 'relationship_targets',
      target: 'Entity B',
      target_color: '#4caf50',
      identifier_color: '#673ab7',
    },
    {
      source: 'Relation C',
      source_color: '#673ab7',
      relation: 'relationship_located-at',
      target: 'Location D',
      target_color: '#00bcd4',
    },
  ],
  then: [
    {
      action: 'CREATE',
      relation: 'relationship_targets',
      source: 'Entity A',
      source_color: '#ff9800',
      target: 'Location D',
      target_color: '#00bcd4',
    },
    {
      action: 'CREATE',
      relation: 'relationship_object',
      source: 'Report A',
      source_color: '#ff9800',
      target: 'Relation D',
      target_color: '#7e57c2',
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
