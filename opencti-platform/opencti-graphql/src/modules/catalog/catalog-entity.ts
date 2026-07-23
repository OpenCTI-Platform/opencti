import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { convertCatalogContractToStix, convertCatalogToStix } from './catalog-entity-converter';
import {
  type BasicStoreEntityCatalog,
  type BasicStoreEntityCatalogContract,
  ENTITY_TYPE_CATALOG,
  ENTITY_TYPE_CATALOG_CONTRACT,
  type StixCatalog,
  type StixCatalogContract,
  type StoreEntityCatalog,
  type StoreEntityCatalogContract,
} from './catalog-entity-types';

// Catalog = version-agnostic listing metadata for a connector family.
// Anything that can change between manifest versions (deployment target,
// capability flags tied to a specific release) must live on CatalogContract
// instead, or "switch to version A" silently reverts to whatever last synced.
const CATALOG_DEFINITION: ModuleDefinition<StoreEntityCatalog, StixCatalog> = {
  type: {
    id: 'catalogs',
    name: ENTITY_TYPE_CATALOG,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      // A connector is uniquely identified by its slug across catalog versions.
      [ENTITY_TYPE_CATALOG]: [{ src: 'slug' }],
    },
    resolvers: {},
  },
  attributes: [
    { name: 'slug', label: 'Slug', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'title', label: 'Title', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'short_description', label: 'Short description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'logo', label: 'Logo', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'use_cases', label: 'Use cases', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
    { name: 'verified', label: 'Verified', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'last_verified_date', label: 'Last verified date', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'playbook_supported', label: 'Playbook supported', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'manager_supported', label: 'Manager supported', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'subscription_link', label: 'Subscription link', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'source_code', label: 'Source code', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'type', label: 'Type', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'last_synced_at', label: 'Last synced at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'is_deleted', label: 'Deleted', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixCatalog) => {
    return stix.title || stix.slug;
  },
  converter_2_1: convertCatalogToStix,
};

// CatalogContract = one immutable snapshot per (slug, version). Everything
// that describes what actually gets deployed for THAT version lives here,
// so switching the active version is a pointer change, not a data loss.
const CATALOG_CONTRACT_DEFINITION: ModuleDefinition<StoreEntityCatalogContract, StixCatalogContract> = {
  type: {
    id: 'catalogContracts',
    name: ENTITY_TYPE_CATALOG_CONTRACT,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      // A contract is uniquely identified by (slug, version).
      [ENTITY_TYPE_CATALOG_CONTRACT]: [{ src: 'slug' }, { src: 'version' }],
    },
    resolvers: {},
  },
  attributes: [
    { name: 'slug', label: 'Slug', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'version', label: 'Version', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'config_schema', label: 'Schema', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'container_version', label: 'Container version', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'container_image', label: 'Container image', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'class_name', label: 'Class name', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'support_version', label: 'Support version', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'max_confidence_level', label: 'Max confidence level', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'is_latest', label: 'Is latest', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'format_version', label: 'Format version', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'last_synced_at', label: 'Last synced at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'is_deleted', label: 'Deleted', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixCatalogContract) => {
    return `${stix.slug}@${stix.version}`;
  },
  converter_2_1: convertCatalogContractToStix,
};

registerDefinition<StoreEntityCatalog, StixCatalog>(CATALOG_DEFINITION);
registerDefinition<StoreEntityCatalogContract, StixCatalogContract>(CATALOG_CONTRACT_DEFINITION);

export type { BasicStoreEntityCatalog, BasicStoreEntityCatalogContract };
