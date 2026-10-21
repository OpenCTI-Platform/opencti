import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../../schema/module';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../../schema/stixDomainObject';
import { ENTITY_TYPE_DEFENSE_GAP, type StixDefenseGap, type StoreEntityDefenseGap } from './defenseGap-types';
import convertDefenseGapToStix from './defenseGap-converter';

const DEFENSE_GAP_DEFINITION: ModuleDefinition<StoreEntityDefenseGap, StixDefenseGap> = {
  type: {
    id: 'defenseGap',
    name: ENTITY_TYPE_DEFENSE_GAP,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      // One record per technique and security platform ('all' for the aggregate)
      [ENTITY_TYPE_DEFENSE_GAP]: [{ src: 'attack_pattern_id' }, { src: 'platform_id' }],
    },
    resolvers: {},
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'attack_pattern_id', label: 'Gap attack pattern', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_ATTACK_PATTERN], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: true },
    { name: 'platform_id', label: 'Gap security platform', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: true },
    { name: 'x_mitre_id', label: 'External ID', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'level', label: 'Gap defense level', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'recommended_action', label: 'Recommended defense action', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'status', label: 'Gap status', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'opened_at', label: 'Gap opened at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'closed_at', label: 'Gap closed at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'computed_at', label: 'Gap computed at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'validation_requests', label: 'Defense validation requests', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'last_validation_requested_at', label: 'Last defense validation request', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixDefenseGap) => {
    return stix.name;
  },
  converter_2_1: convertDefenseGapToStix,
};

registerDefinition(DEFENSE_GAP_DEFINITION);
