import type { DocumentNode } from 'graphql';
import type { ModuleDefinition } from '../schema/module';
import type { AttributeDefinition } from '../schema/attribute-definition';
import type { ManagerDefinition } from '../manager/managerModule';
import type { Resolvers } from '../generated/graphql';
import type { OverviewLayoutCustomization } from './entitySetting/entitySetting-types';

export interface GraphqlSchemaDefinition {
  schema: DocumentNode;
  resolver: Resolvers;
}

export interface AttributesDefinition {
  entityType: string;
  attributes: AttributeDefinition[];
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
  // Attributes of entity types not defined through dataModel (yet)
  attributes?: AttributesDefinition[];
  dataModel?: ModuleDefinition<any, any>[];
  graphqlSchemas?: GraphqlSchemaDefinition[];
  managers?: ManagerDefinition[];
  // Runs once every module is registered: the schema is complete and may be read.
  // Reading it earlier locks it (see usageProtection in schema-attributes).
  init?: () => void;
}
