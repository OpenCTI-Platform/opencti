import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

// region Catalog (one persisted entry per connector, identified by slug)
export const ENTITY_TYPE_CATALOG = 'Catalog';

interface CatalogEntityFields {
  slug: string;
  title: string;
  description: string;
  short_description: string;
  logo: string;
  use_cases: string[];
  verified: boolean;
  last_verified_date: string;
  playbook_supported: boolean;
  max_confidence_level: number;
  support_version: string;
  subscription_link: string;
  source_code: string;
  manager_supported: boolean;
  // Connector image type (EXTERNAL_IMPORT, ...). Named `type` to match the read model;
  // kept optional string to stay compatible with the reserved store `type` field.
  type?: string;
  container_version: string;
  container_image: string;
  class_name: string;
  last_synced_at: Date;
  is_deleted: boolean;
}

export interface BasicStoreEntityCatalog extends BasicStoreEntity, CatalogEntityFields {}

export interface StoreEntityCatalog extends StoreEntity, CatalogEntityFields {}

// Internal object: never exported as a real STIX SDO. Only the fields required by
// the representative function are carried in the minimal STIX wrapper.
export interface StixCatalog extends StixObject {
  slug: string;
  title: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region CatalogContract (one persisted entry per (slug, version))
export const ENTITY_TYPE_CATALOG_CONTRACT = 'CatalogContract';

interface CatalogContractEntityFields {
  catalog_id: string;
  slug: string;
  version: string;
  // Whole JSON Schema blob for this (slug, version), stored as an opaque object.
  schema: Record<string, any>;
  is_latest: boolean;
  format_version: string;
  last_synced_at: Date;
  is_deleted: boolean;
}

export interface BasicStoreEntityCatalogContract extends BasicStoreEntity, CatalogContractEntityFields {}

export interface StoreEntityCatalogContract extends StoreEntity, CatalogContractEntityFields {}

// Internal object: never exported as a real STIX SDO.
export interface StixCatalogContract extends StixObject {
  slug: string;
  version: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion
