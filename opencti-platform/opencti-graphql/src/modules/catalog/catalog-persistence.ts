// opencti-platform/opencti-graphql/src/modules/catalog/catalog-persistence.ts

import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, patchAttribute } from '../../database/middleware';
import { fullEntitiesList } from '../../database/middleware-loader';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { ENTITY_TYPE_CATALOG, ENTITY_TYPE_CATALOG_CONTRACT } from './catalog-entity-types';

import type { BasicStoreEntityCatalog, BasicStoreEntityCatalogContract } from './catalog-entity';

// -- Domain fields (primary definition; storage entities extend these + BasicStoreEntity) --
// Field-for-field match against catalog-entity.ts's registered `attributes` lists.
// NOT derived via Omit<Entity, keyof BasicStoreEntity> - that pattern silently
// stripped every field when BasicStoreEntity carries an index signature (see PR history).

export interface CatalogInput {
  slug: string;
  title: string;
  description: string; // required: BasicStoreEntity mandates description: string, not optional
  short_description?: string;
  logo?: string;
  use_cases: string[];
  verified: boolean;
  last_verified_date?: string;
  playbook_supported: boolean;
  manager_supported: boolean;
  subscription_link?: string;
  source_code?: string;
  type?: string; // connector category (e.g. EXTERNAL_IMPORT) - lives here, NOT on the contract; see open question in review thread
  last_synced_at: string;
  is_deleted: boolean;
}

export interface CatalogContractInput {
  slug: string;
  version: string;
  config_schema?: string;
  container_version?: string;
  container_image?: string;
  class_name?: string;
  support_version?: string;
  max_confidence_level?: number;
  is_latest: boolean;
  format_version?: string;
  last_synced_at: string;
  is_deleted: boolean;
}

// -- Writes --

// Upsert relies on the identifier definition (hashed from `slug`) resolving to the
// same standard_id on every sync - createEntity updates in place if it already exists.
export const upsertCatalog = async (
  context: AuthContext,
  user: AuthUser,
  input: CatalogInput,
): Promise<BasicStoreEntityCatalog> => {
  logApp.debug('[OPENCTI-MODULE] Catalog persistence upserting Catalog', { slug: input.slug });
  const result = await createEntity(context, user, input, ENTITY_TYPE_CATALOG);
  logApp.debug('[OPENCTI-MODULE] Catalog persistence upserted Catalog', { slug: input.slug, id: result.id });
  return result;
};

// Maintains "exactly one is_latest per slug" at write time - not left for a reader to
// arbitrate if the sync manager ever upserts two versions marked latest in the same run.
export const upsertCatalogContract = async (
  context: AuthContext,
  user: AuthUser,
  input: CatalogContractInput,
): Promise<BasicStoreEntityCatalogContract> => {
  if (input.is_latest) {
    const currentLatest = await findLatestContractBySlug(context, user, input.slug);
    if (currentLatest && currentLatest.version !== input.version) {
      logApp.debug('[OPENCTI-MODULE] Catalog persistence demoting previous latest contract', { slug: input.slug, previousVersion: currentLatest.version, newVersion: input.version });
      await patchAttribute(context, user, currentLatest.id, ENTITY_TYPE_CATALOG_CONTRACT, { is_latest: false });
    }
  }
  logApp.debug('[OPENCTI-MODULE] Catalog persistence upserting CatalogContract', { slug: input.slug, version: input.version, is_latest: input.is_latest });
  const result = await createEntity(context, user, input, ENTITY_TYPE_CATALOG_CONTRACT);
  logApp.debug('[OPENCTI-MODULE] Catalog persistence upserted CatalogContract', { slug: input.slug, version: input.version, id: result.id });
  return result;
};

// -- Reads --

export const findAllCatalogs = async (
  context: AuthContext,
  user: AuthUser,
): Promise<BasicStoreEntityCatalog[]> => {
  return fullEntitiesList<BasicStoreEntityCatalog>(context, user, [ENTITY_TYPE_CATALOG]);
};

export const findCatalogBySlug = async (
  context: AuthContext,
  user: AuthUser,
  slug: string,
): Promise<BasicStoreEntityCatalog | undefined> => {
  const results = await fullEntitiesList<BasicStoreEntityCatalog>(context, user, [ENTITY_TYPE_CATALOG], {
    filters: { mode: FilterMode.And, filters: [{ key: ['slug'], values: [slug], operator: FilterOperator.Eq }], filterGroups: [] },
  });
  return results[0];
};

export const findLatestContractsBySlug = async (
  context: AuthContext,
  user: AuthUser,
): Promise<BasicStoreEntityCatalogContract[]> => {
  return fullEntitiesList<BasicStoreEntityCatalogContract>(context, user, [ENTITY_TYPE_CATALOG_CONTRACT], {
    filters: { mode: FilterMode.And, filters: [{ key: ['is_latest'], values: [true], operator: FilterOperator.Eq }], filterGroups: [] },
  });
};

export const findLatestContractBySlug = async (
  context: AuthContext,
  user: AuthUser,
  slug: string,
): Promise<BasicStoreEntityCatalogContract | undefined> => {
  const results = await fullEntitiesList<BasicStoreEntityCatalogContract>(context, user, [ENTITY_TYPE_CATALOG_CONTRACT], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['slug'], values: [slug], operator: FilterOperator.Eq },
        { key: ['is_latest'], values: [true], operator: FilterOperator.Eq },
      ],
      filterGroups: [],
    },
  });
  return results[0];
};

export const findContractBySlugAndVersion = async (
  context: AuthContext,
  user: AuthUser,
  slug: string,
  version: string,
): Promise<BasicStoreEntityCatalogContract | undefined> => {
  const results = await fullEntitiesList<BasicStoreEntityCatalogContract>(context, user, [ENTITY_TYPE_CATALOG_CONTRACT], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['slug'], values: [slug], operator: FilterOperator.Eq },
        { key: ['version'], values: [version], operator: FilterOperator.Eq },
      ],
      filterGroups: [],
    },
  });
  return results[0];
};

// -- Snapshot ingestion (called from catalogManager after a successful fetch) --

// Structural shape of a single flattened contract as produced by the adapters
// (LegacyManifestAdapter / NewManifestAdapter). Kept local/structural since the exact
// adapter export type wasn't confirmed in this session - align with the real
// `CatalogContract` adapter type before merging.
export interface AdapterCatalogContract {
  slug: string;
  title: string;
  description?: string;
  short_description?: string;
  logo?: string;
  use_cases?: string[];
  verified?: boolean;
  last_verified_date?: string;
  playbook_supported?: boolean;
  manager_supported?: boolean;
  subscription_link?: string;
  source_code?: string;
  type?: string;
  config_schema?: object;
  container_version: string;
  container_image?: string;
  class_name?: string;
  support_version?: string;
  max_confidence_level?: number;
  format_version?: string;
}

export interface AdapterInternalCatalog {
  allContracts?: AdapterCatalogContract[];
}

// Dependency-free numeric dot-segment comparison, not full semver (no pre-release/build
// metadata handling). Replaces "latest by array order", which was the original bug.
export const compareVersions = (a: string, b: string): number => {
  const partsA = (a ?? '').split('.').map((n) => parseInt(n, 10));
  const partsB = (b ?? '').split('.').map((n) => parseInt(n, 10));
  const length = Math.max(partsA.length, partsB.length);
  for (let i = 0; i < length; i += 1) {
    const numA = Number.isNaN(partsA[i]) ? 0 : (partsA[i] ?? 0);
    const numB = Number.isNaN(partsB[i]) ? 0 : (partsB[i] ?? 0);
    if (numA !== numB) return numA - numB;
  }
  return 0;
};

// Persists one fetched manifest snapshot: groups contracts by slug, determines the real
// latest version per slug via compareVersions (not array order), upserts one Catalog per
// slug (stable fields, taken from the latest version) and one CatalogContract per
// (slug, version) with is_latest set accordingly.
//
// Deliberately does NOT handle tombstoning entities that disappeared from the manifest
// (is_deleted) - open question from an earlier review, still unresolved, out of scope here.
export const persistCatalogSnapshot = async (
  context: AuthContext,
  user: AuthUser,
  internalCatalog: AdapterInternalCatalog,
): Promise<void> => {
  const contracts = internalCatalog.allContracts ?? [];
  if (contracts.length === 0) {
    logApp.info('[OPENCTI-MODULE] Catalog persistence skipping snapshot (no contracts)');
    return;
  }
  logApp.info('[OPENCTI-MODULE] Catalog persistence starting snapshot', { contractCount: contracts.length });

  const now = new Date().toISOString();
  const bySlug = new Map<string, AdapterCatalogContract[]>();
  contracts.forEach((contract) => {
    const existing = bySlug.get(contract.slug) ?? [];
    existing.push(contract);
    bySlug.set(contract.slug, existing);
  });

  const slugEntries = Array.from(bySlug.entries());
  for (let i = 0; i < slugEntries.length; i += 1) {
    const [slug, versions] = slugEntries[i];
    const sorted = [...versions].sort((a, b) => compareVersions(b.container_version, a.container_version));
    const latest = sorted[0];

    await upsertCatalog(context, user, {
      slug,
      title: latest.title,
      description: latest.description ?? '',
      short_description: latest.short_description,
      logo: latest.logo,
      use_cases: latest.use_cases ?? [],
      verified: latest.verified ?? false,
      last_verified_date: latest.last_verified_date,
      playbook_supported: latest.playbook_supported ?? false,
      manager_supported: latest.manager_supported ?? false,
      subscription_link: latest.subscription_link,
      source_code: latest.source_code,
      type: latest.type,
      last_synced_at: now,
      is_deleted: false,
    });

    logApp.debug('[OPENCTI-MODULE] Catalog persistence upserting contracts for slug', { slug, versionCount: sorted.length });
    for (let v = 0; v < sorted.length; v += 1) {
      const contract = sorted[v];

      await upsertCatalogContract(context, user, {
        slug,
        version: contract.container_version,
        config_schema: JSON.stringify(contract.config_schema ?? {}),
        container_version: contract.container_version,
        container_image: contract.container_image,
        class_name: contract.class_name,
        support_version: contract.support_version,
        max_confidence_level: contract.max_confidence_level,
        format_version: contract.format_version,
        is_latest: v === 0,
        last_synced_at: now,
        is_deleted: false,
      });
    }
  }

  logApp.info('[OPENCTI-MODULE] Catalog persistence snapshot complete', { slugCount: bySlug.size });
};
