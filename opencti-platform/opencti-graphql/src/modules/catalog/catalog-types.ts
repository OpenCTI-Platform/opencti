export const COMPOSER_FF = 'COMPOSER';

export interface CatalogContract {
  $schema: string;
  $id: string;
  title: string;
  description: string;
  type: string;
  container_type: string;
  container_image: string;
  properties: object;
  required: string[];
  additionalProperties: boolean;
}

export interface CatalogDefinition {
  id: string;
  name: string;
  description: string;
  contracts: Array<CatalogContract>;
}

export interface CatalogType {
  definition: CatalogDefinition;
  graphql: GraphqlCatalog;
}

// region Database types
export interface GraphqlCatalog {
  id: string;
  entity_type: string;
  standard_id: string;
  parent_types: string[];
  name: string;
  description: string;
  contracts: string[];
}
