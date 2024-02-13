import { v4 as uuidv4 } from 'uuid';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_DECAY_RULE, type StixDecayRule, type StoreEntityDecayRule } from './decayRule-types';
import convertDecayRuleToStix from './decayRule-converter';

const DECAY_RULE_DEFINITION: ModuleDefinition<StoreEntityDecayRule, StixDecayRule> = {
  type: {
    id: 'decayRule',
    name: ENTITY_TYPE_DECAY_RULE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_DECAY_RULE]: () => uuidv4()
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'order', label: 'Order', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'built_in', label: 'Built-in', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'active', label: 'Status', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'decay_lifetime', label: 'Lifetime', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'decay_pound', label: 'Decay factor', type: 'numeric', precision: 'float', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'decay_points', label: 'Reaction points', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
    { name: 'decay_revoke_score', label: 'Revoke score', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'decay_observable_types', label: 'Indicator observable types', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixDecayRule) => {
    return stix.name;
  },
  converter: convertDecayRuleToStix
};

registerDefinition(DECAY_RULE_DEFINITION);
