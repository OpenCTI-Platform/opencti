import managerConfigurationTypeDefs from './managerConfiguration.graphql';
import managerConfigurationResolvers from './managerConfiguration-resolvers';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import type { StixManagerConfiguration, StoreEntityManagerConfiguration } from './managerConfiguration-types';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from './managerConfiguration-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import convertManagerConfigurationToStix from './managerConfiguration-converter';

const MANAGER_CONFIGURATION_DEFINITION: ModuleDefinition<StoreEntityManagerConfiguration, StixManagerConfiguration> = {
  type: {
    id: 'managerConfigurations',
    name: ENTITY_TYPE_MANAGER_CONFIGURATION,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  graphql: {
    schema: managerConfigurationTypeDefs,
    resolver: managerConfigurationResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_MANAGER_CONFIGURATION]: [{ src: 'manager_id' }]
    },
    resolvers: {
      manager_id(data: object) {
        return (data as unknown as string).toUpperCase();
      },
    },
  },
  attributes: [
    { name: 'manager_id', label: 'Manager ID', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'manager_running', label: 'Running', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'manager_setting', label: 'Setting', type: 'object', format: 'flat', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'last_run_start_date', label: 'Last run start date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'last_run_end_date', label: 'Last run end date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixManagerConfiguration) => {
    return stix.manager_id;
  },
  converter: convertManagerConfigurationToStix
};

registerDefinition(MANAGER_CONFIGURATION_DEFINITION);
