import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { isFeatureEnabled } from '../../config/conf';
import { convertCatalogContractToStix, convertCatalogLogoToStix, convertCatalogManifestToStix } from './catalog-entity-converter';
import {
  type BasicStoreEntityCatalogContract,
  type BasicStoreEntityCatalogLogo,
  type BasicStoreEntityCatalogManifest,
  ENTITY_TYPE_CATALOG_MANIFEST,
  ENTITY_TYPE_CATALOG_CONTRACT,
  ENTITY_TYPE_CATALOG_LOGO,
  type StixCatalogContract,
  type StixCatalogManifest,
  type StixCatalogLogo,
  type StoreEntityCatalogContract,
  type StoreEntityCatalogManifest,
  type StoreEntityCatalogLogo,
} from './catalog-entity-types';
import { DECOUPLING_CONNECTOR_VERSIONS } from './catalog-constants';

// CatalogContract = one persisted entry per (slug, version).
// All connector metadata lives here since any field can vary between versions.
const CATALOG_CONTRACT_DEFINITION: ModuleDefinition<StoreEntityCatalogContract, StixCatalogContract> = {
  type: {
    id: 'catalogContracts',
    name: ENTITY_TYPE_CATALOG_CONTRACT,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CATALOG_CONTRACT]: [{ src: 'slug' }, { src: 'version' }],
    },
    resolvers: {},
  },
  attributes: [
    { name: 'catalog_id', label: 'Catalog ID', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'slug', label: 'Slug', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'version', label: 'Version', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    // Connector metadata - versioned
    { name: 'title', label: 'Title', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'short_description', label: 'Short description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'logo', label: 'Logo', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'logo_ref', label: 'Logo reference', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'use_cases', label: 'Use cases', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    { name: 'verified', label: 'Verified', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'last_verified_date', label: 'Last verified date', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'playbook_supported', label: 'Playbook supported', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'manager_supported', label: 'Manager supported', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'subscription_link', label: 'Subscription link', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'source_code', label: 'Source code', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'type', label: 'Type', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    // Deployment data
    { name: 'config_schema', label: 'Schema', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'image', label: 'Image', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'support_version', label: 'Support version', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'max_confidence_level', label: 'Max confidence level', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixCatalogContract) => {
    return `${stix.slug}@${stix.version}`;
  },
  converter_2_1: convertCatalogContractToStix,
};

if (isFeatureEnabled(DECOUPLING_CONNECTOR_VERSIONS)) {
  registerDefinition<StoreEntityCatalogContract, StixCatalogContract>(CATALOG_CONTRACT_DEFINITION);
}

const CATALOG_LOGO_DEFINITION: ModuleDefinition<StoreEntityCatalogLogo, StixCatalogLogo> = {
  type: {
    id: 'catalogLogos',
    name: ENTITY_TYPE_CATALOG_LOGO,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CATALOG_LOGO]: [{ src: 'hash' }],
    },
    resolvers: {},
  },
  attributes: [
    { name: 'hash', label: 'Hash', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'data_uri', label: 'Data URI', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'last_synced_at', label: 'Last synced at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixCatalogLogo) => {
    return stix.hash;
  },
  converter_2_1: convertCatalogLogoToStix,
};

if (isFeatureEnabled(DECOUPLING_CONNECTOR_VERSIONS)) {
  registerDefinition<StoreEntityCatalogLogo, StixCatalogLogo>(CATALOG_LOGO_DEFINITION);
}

const CATALOG_MANIFEST_DEFINITION: ModuleDefinition<StoreEntityCatalogManifest, StixCatalogManifest> = {
  type: {
    id: 'catalogManifests',
    name: ENTITY_TYPE_CATALOG_MANIFEST,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CATALOG_MANIFEST]: [{ src: 'source_uri' }],
    },
    resolvers: {},
  },
  attributes: [
    { name: 'source_uri', label: 'Source URI', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'catalog_id', label: 'Catalog ID', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'revision', label: 'Revision', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'manifest_version', label: 'Manifest version', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'version', label: 'Product version', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixCatalogManifest) => {
    return stix.catalog_id;
  },
  converter_2_1: convertCatalogManifestToStix,
};

if (isFeatureEnabled(DECOUPLING_CONNECTOR_VERSIONS)) {
  registerDefinition<StoreEntityCatalogManifest, StixCatalogManifest>(CATALOG_MANIFEST_DEFINITION);
}

export type { BasicStoreEntityCatalogContract, BasicStoreEntityCatalogLogo, BasicStoreEntityCatalogManifest };
