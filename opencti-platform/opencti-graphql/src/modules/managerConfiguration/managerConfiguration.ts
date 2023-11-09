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
    { name: 'manager_id', type: 'string', mandatoryType: 'internal', multiple: false, upsert: false },
    { name: 'manager_running', type: 'boolean', mandatoryType: 'internal', multiple: false, upsert: false },
    { name: 'last_run_start_date', type: 'date', mandatoryType: 'internal', multiple: false, upsert: false },
    { name: 'last_run_end_date', type: 'date', mandatoryType: 'internal', multiple: false, upsert: false },
  ],
  relations: [],
  representative: (stix: StixManagerConfiguration) => {
    return stix.manager_id;
  },
  converter: convertManagerConfigurationToStix
};

registerDefinition(MANAGER_CONFIGURATION_DEFINITION);
