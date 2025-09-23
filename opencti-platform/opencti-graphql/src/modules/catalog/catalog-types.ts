export type IngestionConnectorType = 'INTERNAL_ENRICHMENT' | 'EXTERNAL_IMPORT' | 'INTERNAL_EXPORT_FILE' | 'INTERNAL_IMPORT_FILE';

type TypeMap = {
  string: string;
  integer: number;
  dict: object;
  array: string[];
  boolean: boolean;
};

type TypedProperty<K extends keyof TypeMap = keyof TypeMap> = {
  type: K;
  default: TypeMap[K];
  description: string;
  format?: string;
};

export interface CatalogContract {
  title: string,
  slug: string,
  description: string,
  short_description: string,
  logo: string,
  use_cases: string[],
  verified: boolean,
  last_verified_date: string,
  playbook_supported: boolean,
  max_confidence_level: number,
  support_version: string,
  subscription_link: string,
  source_code: string,
  manager_supported: boolean,
  container_version: string,
  container_image: string,
  container_type: IngestionConnectorType,
  config_schema: {
    $schema: string,
    $id: string,
    type: string,
    properties: {
      [key: string]: TypedProperty
    },
    required: string[],
    additionalProperties: boolean,
  }
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
