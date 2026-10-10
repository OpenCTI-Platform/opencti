import type { ModuleDescriptor } from './modules/module-descriptor';
import { registerDefinition } from './schema/module';
import { registerGraphqlSchema } from './graphql/schema';
import { registerManager } from './manager/managerModule';
import dataSanityModule from './modules/dataSanity/dataSanity-module';
import userMergeModule from './modules/userMerge/userMerge-module';

// Modules migrated to explicit registration.
// The others still register themselves on import, through modules/index and manager/index.
export const MODULE_DESCRIPTORS: ModuleDescriptor[] = [
  dataSanityModule,
  userMergeModule,
];

let modulesRegistered = false;

// Each phase runs for every module before the next phase starts: definitions, graphql schemas,
// managers, then init. The whole of it runs after modules/index, so a migrated definition is
// registered after the graphql of the modules still registered on import, against the order
// modules/index documents. That is safe only while nothing reads the model at import time:
// usageProtection catches an early read of attributes or refs, not of types, converters or validators.
// Must run before anything reads the schema (selectEntityType, createSchema, startAllManagers).
export const registerModules = (descriptors: ModuleDescriptor[] = MODULE_DESCRIPTORS) => {
  if (modulesRegistered) {
    return;
  }
  modulesRegistered = true;
  descriptors.forEach(({ definitions = [] }) => definitions.forEach((definition) => registerDefinition(definition)));
  descriptors.forEach(({ graphqlSchemas = [] }) => graphqlSchemas.forEach((graphqlSchema) => registerGraphqlSchema(graphqlSchema)));
  descriptors.forEach(({ managers = [] }) => managers.forEach((manager) => registerManager(manager)));
  descriptors.forEach(({ init }) => init?.());
};
