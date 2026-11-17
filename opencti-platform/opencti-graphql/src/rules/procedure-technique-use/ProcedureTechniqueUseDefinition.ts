import { RELATION_IMPLEMENTS_TECHNIQUE, RELATION_USES } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../../modules/threatActorIndividual/threatActorIndividual-types';
import { ENTITY_TYPE_PROCEDURE } from '../../modules/procedure/procedure-types';
import type { RuleDefinition } from '../../types/rules';

// Entities whose use of a procedure propagates to the techniques the procedure implements.
export const USING_TYPES = [ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_THREAT_ACTOR_GROUP, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL];

const id = 'procedure_technique_use';
const name = 'Usage propagation of procedure techniques';
const description = 'Propagate a usage of a procedure to the techniques it implements.';
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
      relation: 'relationship_implements-technique',
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
const scan = { types: [RELATION_USES], fromTypes: USING_TYPES, toTypes: [ENTITY_TYPE_PROCEDURE] };

// For live
const attributes = [
  { name: 'start_time' },
  { name: 'stop_time' },
  { name: 'confidence' },
  { name: 'object_marking_refs' },
];
const scopes = [
  { filters: { types: [RELATION_USES], fromTypes: USING_TYPES, toTypes: [ENTITY_TYPE_PROCEDURE] }, attributes },
  { filters: { types: [RELATION_IMPLEMENTS_TECHNIQUE], fromTypes: [ENTITY_TYPE_PROCEDURE], toTypes: [ENTITY_TYPE_ATTACK_PATTERN] }, attributes },
];

const definition: RuleDefinition = { id, name, description, scan, scopes, category, display };
export default definition;
