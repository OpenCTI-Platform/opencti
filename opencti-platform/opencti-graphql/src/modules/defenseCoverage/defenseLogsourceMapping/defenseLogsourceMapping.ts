import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { ruleLogsource } from '../../../schema/attribute-definition';
import { type ModuleDefinition, registerDefinition } from '../../../schema/module';
import { ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING, type StixDefenseLogsourceMapping, type StoreEntityDefenseLogsourceMapping } from './defenseLogsourceMapping-types';
import convertDefenseLogsourceMappingToStix from './defenseLogsourceMapping-converter';

const DEFENSE_LOGSOURCE_MAPPING_DEFINITION: ModuleDefinition<StoreEntityDefenseLogsourceMapping, StixDefenseLogsourceMapping> = {
  type: {
    id: 'defenseLogsourceMapping',
    name: ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      // One entry per log source (category | product | service)
      [ENTITY_TYPE_DEFENSE_LOGSOURCE_MAPPING]: [{ src: 'mapping_key' }],
    },
    resolvers: {},
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'mapping_key', label: 'Log source mapping key', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: false },
    ruleLogsource,
    { name: 'data_components', label: 'Mapped data components', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
    { name: 'active', label: 'Status', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'built_in', label: 'Built-in', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixDefenseLogsourceMapping) => {
    return stix.name;
  },
  converter_2_1: convertDefenseLogsourceMappingToStix,
};

registerDefinition(DEFENSE_LOGSOURCE_MAPPING_DEFINITION);
