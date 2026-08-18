import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import {
  type BasicStoreEntityCatalogContract,
  type BasicStoreEntityCatalogManifest,
  ENTITY_TYPE_CATALOG_MANIFEST,
  ENTITY_TYPE_CATALOG_CONTRACT,
  type StoreEntityCatalogContract,
  type StoreEntityCatalogManifest,
} from './catalog-types';
import type { AttributeDefinition } from '../../schema/attribute-definition';

export const CATALOG_CONTRACT_MAPPINGS: AttributeDefinition[] = [
  { name: 'catalog_id', label: 'Catalog ID', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'contract_id', label: 'Catalog Contract ID', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'content_hash', label: 'Catalog Contract content hash', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'title', label: 'Title', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'slug', label: 'Slug', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'short_description', label: 'Short description', type: 'string', format: 'text', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'logo_uri', label: 'Logo URI in file storage', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'use_cases', label: 'Use cases', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: true, upsert: false, isFilterable: true },
  { name: 'verified', label: 'Verified', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'last_verified_date', label: 'Last verified date', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'playbook_supported', label: 'Playbook supported', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'max_confidence_level', label: 'Max confidence level', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'support_version', label: 'Support version', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'subscription_link', label: 'Subscription link', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'source_code', label: 'Source code', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'manager_supported', label: 'Manager supported', type: 'boolean', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'version', label: 'Version', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'image', label: 'Image', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'connector_type', label: 'Connector type', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'config_schema', label: 'Configuration schema', type: 'object', format: 'raw', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  { name: 'license_type', label: 'License type', type: 'string', format: 'enum', values: ['Free', 'Commercial'], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  { name: 'solution_categories', label: 'Solution categories', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
  { name: 'contact', label: 'Contact', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
];

// CatalogContract = one persisted entry per (slug, version).
// All connector metadata lives here since any field can vary between versions.
const CATALOG_CONTRACT_DEFINITION: ModuleDefinition<StoreEntityCatalogContract, any> = {
  type: {
    id: 'catalogContracts',
    name: ENTITY_TYPE_CATALOG_CONTRACT,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {},
    resolvers: {},
  },
  attributes: CATALOG_CONTRACT_MAPPINGS,
  relations: [],
  // Irrelevant as no corresponding Stix object.
  // To remove once entity/module definition helper is reworked.
  representative: () => {
    throw new Error('Should not be called');
  },
  converter_2_1: () => {
    throw new Error('Should not be called');
  },
};

registerDefinition<StoreEntityCatalogContract, any>(CATALOG_CONTRACT_DEFINITION);

const CATALOG_MANIFEST_DEFINITION: ModuleDefinition<StoreEntityCatalogManifest, any> = {
  type: {
    id: 'catalogManifests',
    name: ENTITY_TYPE_CATALOG_MANIFEST,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CATALOG_MANIFEST]: [{ src: 'catalog_id' }],
    },
    resolvers: {},
  },
  attributes: [
    { name: 'source_uri', label: 'Source URI', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'catalog_id', label: 'Catalog ID', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'revision', label: 'Revision', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'version', label: 'Product version', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  ],
  relations: [],
  // Irrelevant as no corresponding Stix object.
  // To remove once entity/module definition helper is reworked.
  representative: () => {
    throw new Error('Should not be called');
  },
  converter_2_1: () => {
    throw new Error('Should not be called');
  },
};

registerDefinition<StoreEntityCatalogManifest, any>(CATALOG_MANIFEST_DEFINITION);

export type { BasicStoreEntityCatalogContract, BasicStoreEntityCatalogManifest };
