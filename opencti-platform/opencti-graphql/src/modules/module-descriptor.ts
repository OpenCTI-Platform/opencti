import type { DocumentNode } from 'graphql';
import type { ModuleDefinition } from '../schema/module';
import type { ManagerDefinition } from '../manager/managerModule';
import type { Resolvers } from '../generated/graphql';
import type { OverviewLayoutCustomization } from './entitySetting/entitySetting-types';

// Resolvers are merged across modules (mergeResolvers): a module extending an interface defined elsewhere
// provides some of its fields only, without the __resolveType the interface's own resolvers provide.
export type ModuleResolvers = { [Type in keyof Resolvers]?: Partial<Resolvers[Type]> };

export interface GraphqlSchemaDefinition {
  schema: DocumentNode;
  resolver: ModuleResolvers;
}

export interface OverviewLayoutDefinition {
  entityType: string;
  layout: OverviewLayoutCustomization[];
}

// Everything a module contributes to the platform at boot, as plain data.
// Importing a module descriptor has no side effect: the composition root
// decides when each part is registered.
export interface ModuleDescriptor {
  id: string;
  // Default overview layouts of entity types not defined through dataModel (yet)
  overviewLayouts?: OverviewLayoutDefinition[];
  dataModel?: ModuleDefinition<any, any>[];
  graphqlSchemas?: GraphqlSchemaDefinition[];
  managers?: ManagerDefinition[];
  // Runs once every module is registered: the schema is complete and may be read.
  // Reading it earlier locks it (see usageProtection in schema-attributes).
  init?: () => void;
}
