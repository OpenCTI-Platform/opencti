import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import type { StixDataSanityConfiguration, StoreEntityDataSanityConfiguration } from './dataSanityConfiguration-types';
import { ENTITY_TYPE_DATA_SANITY_CONFIGURATION } from './dataSanityConfiguration-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import convertDataSanityConfigurationToStix from './dataSanityConfiguration-converter';
import { v4 as uuidv4 } from 'uuid';

const DATA_SANITY_CONFIGURATION_DEFINITION: ModuleDefinition<StoreEntityDataSanityConfiguration, StixDataSanityConfiguration> = {
  type: {
    id: 'dataSanityConfiguration',
    name: ENTITY_TYPE_DATA_SANITY_CONFIGURATION,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_DATA_SANITY_CONFIGURATION]: () => uuidv4(),
    },
  },
  attributes: [
    {
      name: 'maintenance_planning',
      label: 'Maintenance planning',
      type: 'string',
      format: 'text',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: true,
      isFilterable: false,
    },
  ],
  relations: [],
  representative: (_stix: StixDataSanityConfiguration) => {
    return 'DataSanityConfiguration';
  },
  converter_2_1: convertDataSanityConfigurationToStix,
};

registerDefinition(DATA_SANITY_CONFIGURATION_DEFINITION);
