import type { BasicStoreEntity, StoreEntity } from '../../types/store';

// region DTO types
export type IngestionConnectorType = string;

type TypeMap = {
  string: string;
  integer: number;
  dict: object;
  array: string[];
  boolean: boolean;
};

export type TypedProperty<K extends keyof TypeMap = keyof TypeMap> = {
  type: K;
  default?: TypeMap[K];
  description?: string;
  format?: string;
};

export interface CatalogContract {
  title: string;
  slug: string;
  description: string;
  short_description: string;
  logo: string | null;
  use_cases: string[];
  verified: boolean;
  last_verified_date: string | null;
  playbook_supported: boolean;
  max_confidence_level: number;
  support_version: string | null;
  subscription_link: string | null;
  source_code: string;
  manager_supported: boolean;
  container_version: string;
  container_image: string;
  container_type: IngestionConnectorType;
  config_schema: {
    $schema: string;
    $id: string;
    type: string;
    properties: {
      [key: string]: TypedProperty;
    };
    required: string[];
    additionalProperties: boolean;
  };
  license_type: 'Free' | 'Commercial' | null;
  solution_categories: string[];
  contact: string | null;
}

export interface CatalogDefinition {
  id: string;
  name: string;
  description: string;
  version: string;
  contracts: Array<CatalogContract>;
}
// endregion

export interface CatalogType {
  definition: CatalogDefinition;
  graphql: GraphqlCatalog;
}

// region Api types
export type GraphqlCatalogContract = CatalogContract;
export interface GraphqlCatalog {
  id: string;
  entity_type: string;
  standard_id: string;
  parent_types: string[];
  name: string;
  description: string;
  contracts: string[]; // JSON.Stringified GraphqlCatalogContract items
}
// endregion

// region Database types

export const ENTITY_TYPE_CATALOG_CONTRACT = 'CatalogContract';
export const ENTITY_TYPE_CATALOG_MANIFEST = 'CatalogManifest';

/**
 * Fields specific to the `CatalogContract` entity.
 * Also reused to embed the contract in `Connector` entities.
 */
export interface CatalogContractEntityFields {
  catalog_id: string;
  contract_id: string;
  content_hash: string;
  title: string;
  slug: string;
  description: string;
  short_description: string;
  logo_uri?: string;
  use_cases?: string[];
  verified: boolean;
  last_verified_date?: string;
  playbook_supported: boolean;
  max_confidence_level: number;
  support_version?: string;
  subscription_link?: string;
  source_code?: string;
  manager_supported: boolean;
  version: string;
  contract_version: string;
  image: string;
  connector_type: IngestionConnectorType;
  config_schema: {
    $schema: string;
    $id: string;
    type: string;
    properties: {
      [key: string]: TypedProperty;
    };
    required: string[];
    additionalProperties: boolean;
  };
  license_type?: 'Free' | 'Commercial';
  solution_categories: string[];
  contact?: string;
};

export interface BasicStoreEntityCatalogContract extends BasicStoreEntity, CatalogContractEntityFields {}

export interface StoreEntityCatalogContract extends StoreEntity, CatalogContractEntityFields {}

interface CatalogManifestEntityFields {
  revision: string;
  source_uri: string;
  catalog_id: string;
  name: string;
  description: string;
  version: string;
}

export interface BasicStoreEntityCatalogManifest extends BasicStoreEntity, CatalogManifestEntityFields {}

export interface StoreEntityCatalogManifest extends StoreEntity, CatalogManifestEntityFields {}

export interface CatalogContractDeletion {
  idToDelete: string;
}

export type CatalogContractUpdate = Required<{
  [TKey in keyof CatalogContractEntityFields]: CatalogContractEntityFields[TKey] | null;
}> & { internal_id: string; standard_id: string };

export type CatalogContractCreation = CatalogContractEntityFields & { internal_id: string; standard_id: string };

export type CatalogManifestUpsert = CatalogManifestEntityFields & { internal_id: string; standard_id: string };
// endregion
