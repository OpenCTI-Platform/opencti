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

// Each phase runs for every module before the next phase starts, keeping the order
// the import barrels enforced: definitions, graphql schemas, managers, then init.
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
