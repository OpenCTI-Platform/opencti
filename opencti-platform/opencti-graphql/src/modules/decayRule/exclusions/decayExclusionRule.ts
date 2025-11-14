import { v4 as uuidv4 } from 'uuid';
import { ENTITY_TYPE_DECAY_EXCLUSION_RULE, StixDecayExclusionRule, StoreEntityDecayExclusionRule } from './decayExclusionRule-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../../schema/module';
import convertDecayExclusionRuleToStix from './decayExclusionRule-converter';
import { isFeatureEnabled } from '../../../config/conf';

const DECAY_EXCLUSION_RULE_DEFINITION: ModuleDefinition<StoreEntityDecayExclusionRule, StixDecayExclusionRule> = {
  type: {
    id: 'decayExclusionRule',
    name: ENTITY_TYPE_DECAY_EXCLUSION_RULE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_DECAY_EXCLUSION_RULE]: () => uuidv4()
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'active', label: 'Status', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'decay_exclusion_observable_types', label: 'Indicator filters', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixDecayExclusionRule) => {
    return stix.name;
  },
  converter_2_1: convertDecayExclusionRuleToStix
};

const isDecayExclusionRuleEnabled = isFeatureEnabled('DECAY_EXCLUSION_RULE_ENABLED');

if (isDecayExclusionRuleEnabled) {
  registerDefinition(DECAY_EXCLUSION_RULE_DEFINITION);
}
