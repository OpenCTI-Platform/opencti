import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { convertCatalogContractToStix, convertCatalogLogoToStix } from './catalog-entity-converter';
import {
  type BasicStoreEntityCatalogContract,
  type BasicStoreEntityCatalogLogo,
  ENTITY_TYPE_CATALOG_CONTRACT,
  ENTITY_TYPE_CATALOG_LOGO,
  type StixCatalogContract,
  type StixCatalogLogo,
  type StoreEntityCatalogContract,
  type StoreEntityCatalogLogo,
} from './catalog-entity-types';

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
    { name: 'is_latest', label: 'Is latest', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'format_version', label: 'Format version', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'last_synced_at', label: 'Last synced at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixCatalogContract) => {
    return `${stix.slug}@${stix.version}`;
  },
  converter_2_1: convertCatalogContractToStix,
};

registerDefinition<StoreEntityCatalogContract, StixCatalogContract>(CATALOG_CONTRACT_DEFINITION);

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

registerDefinition<StoreEntityCatalogLogo, StixCatalogLogo>(CATALOG_LOGO_DEFINITION);

export type { BasicStoreEntityCatalogContract, BasicStoreEntityCatalogLogo };
