import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

// region CatalogContract (one persisted entry per (slug, version))
// All connector metadata lives here because every field can vary between versions.
export const ENTITY_TYPE_CATALOG_CONTRACT = 'CatalogContract';
export const ENTITY_TYPE_CATALOG_LOGO = 'CatalogLogo';
export const ENTITY_TYPE_CATALOG_MANIFEST = 'CatalogManifest';

interface CatalogContractEntityFields {
  catalog_id: string;
  slug: string;
  version: string;
  // Connector metadata - all versioned, can differ between releases
  title: string;
  description: string;
  short_description: string;
  logo?: string;
  logo_ref?: string;
  use_cases: string[];
  verified: boolean;
  last_verified_date: string;
  playbook_supported: boolean;
  manager_supported: boolean;
  subscription_link: string;
  source_code: string;
  // Connector image type (EXTERNAL_IMPORT, ...). Named `type` to match the read model.
  type?: string;
  // Deployment data for this specific version
  config_schema: string; // stored as JSON string
  image: string; // container image name
  support_version: string;
  max_confidence_level: number;
}

export interface BasicStoreEntityCatalogContract extends BasicStoreEntity, CatalogContractEntityFields {}

export interface StoreEntityCatalogContract extends StoreEntity, CatalogContractEntityFields {}

interface CatalogLogoEntityFields {
  hash: string;
  data_uri: string;
}

export interface BasicStoreEntityCatalogLogo extends BasicStoreEntity, CatalogLogoEntityFields {}

export interface StoreEntityCatalogLogo extends StoreEntity, CatalogLogoEntityFields {}

interface CatalogManifestEntityFields {
  source_uri: string;
  catalog_id: string;
  revision: string;
  manifest_version?: string;
  version?: string;
}

export interface BasicStoreEntityCatalogManifest extends BasicStoreEntity, CatalogManifestEntityFields {}

export interface StoreEntityCatalogManifest extends StoreEntity, CatalogManifestEntityFields {}

// Internal object: never exported as a real STIX SDO.
export interface StixCatalogContract extends StixObject {
  slug: string;
  version: string;
  title: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}

export interface StixCatalogLogo extends StixObject {
  hash: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}

export interface StixCatalogManifest extends StixObject {
  source_uri: string;
  catalog_id: string;
  revision: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion
