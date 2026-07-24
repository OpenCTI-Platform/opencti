// opencti-platform/opencti-graphql/src/modules/catalog/catalog-persistence.ts

import { createHash } from 'node:crypto';
import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, deleteElementById, patchAttribute } from '../../database/middleware';
import { fullEntitiesList } from '../../database/middleware-loader';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { ENTITY_TYPE_CATALOG_CONTRACT, ENTITY_TYPE_CATALOG_LOGO } from './catalog-entity-types';

import type { BasicStoreEntityCatalogContract, BasicStoreEntityCatalogLogo } from './catalog-entity';

export interface CatalogContractInput {
  slug: string;
  version: string;
  title: string;
  description: string;
  short_description?: string;
  logo?: string;
  logo_ref?: string;
  use_cases: string[];
  verified: boolean;
  last_verified_date?: string;
  playbook_supported: boolean;
  manager_supported: boolean;
  subscription_link?: string;
  source_code?: string;
  type?: string;
  // Deployment data
  config_schema?: string;
  image?: string;
  support_version?: string;
  max_confidence_level?: number;
  is_latest: boolean;
  format_version?: string;
  last_synced_at: string;
}

export interface CatalogLogoInput {
  hash: string;
  data_uri: string;
  last_synced_at: string;
}

// -- Writes --

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

export const upsertCatalogLogo = async (
  context: AuthContext,
  user: AuthUser,
  input: CatalogLogoInput,
): Promise<BasicStoreEntityCatalogLogo> => {
  return createEntity(context, user, input, ENTITY_TYPE_CATALOG_LOGO);
};

// -- Reads --

export const findLatestContractsBySlug = async (
  context: AuthContext,
  user: AuthUser,
): Promise<BasicStoreEntityCatalogContract[]> => {
  return fullEntitiesList<BasicStoreEntityCatalogContract>(context, user, [ENTITY_TYPE_CATALOG_CONTRACT], {
    filters: { mode: FilterMode.And, filters: [{ key: ['is_latest'], values: [true], operator: FilterOperator.Eq }], filterGroups: [] },
  });
};

export const findAllCatalogContracts = async (
  context: AuthContext,
  user: AuthUser,
): Promise<BasicStoreEntityCatalogContract[]> => {
  return fullEntitiesList<BasicStoreEntityCatalogContract>(context, user, [ENTITY_TYPE_CATALOG_CONTRACT]);
};

export const findCatalogLogosByRefs = async (
  context: AuthContext,
  user: AuthUser,
  refs: string[],
): Promise<BasicStoreEntityCatalogLogo[]> => {
  if (refs.length === 0) return [];
  return fullEntitiesList<BasicStoreEntityCatalogLogo>(context, user, [ENTITY_TYPE_CATALOG_LOGO], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['hash'], values: refs, operator: FilterOperator.Eq }],
      filterGroups: [],
    },
  });
};

export const findAllCatalogLogos = async (
  context: AuthContext,
  user: AuthUser,
): Promise<BasicStoreEntityCatalogLogo[]> => {
  return fullEntitiesList<BasicStoreEntityCatalogLogo>(context, user, [ENTITY_TYPE_CATALOG_LOGO]);
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
  version?: string;
  container_version?: string;
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
  container_type?: string;
  config_schema?: object;
  image?: string;
  container_image?: string;
  support_version?: string;
  max_confidence_level?: number;
  format_version?: string;
}

export interface AdapterInternalCatalog {
  allContracts?: AdapterCatalogContract[];
}

const getContractVersion = (contract: AdapterCatalogContract): string => {
  return contract.version ?? contract.container_version ?? '';
};

const getContractImage = (contract: AdapterCatalogContract): string | undefined => {
  return contract.image ?? contract.container_image;
};

const getContractType = (contract: AdapterCatalogContract): string | undefined => {
  return contract.type ?? contract.container_type;
};

const computeLogoHash = (logo: string): string => {
  return createHash('sha256').update(logo).digest('hex');
};

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

  const existingContracts = await findAllCatalogContracts(context, user);

  const now = new Date().toISOString();
  const seenLogoHashes = new Set<string>();
  const bySlug = new Map<string, AdapterCatalogContract[]>();
  contracts.forEach((contract) => {
    const existing = bySlug.get(contract.slug) ?? [];
    existing.push(contract);
    bySlug.set(contract.slug, existing);
  });

  const slugEntries = Array.from(bySlug.entries());
  for (let i = 0; i < slugEntries.length; i += 1) {
    const [slug, versions] = slugEntries[i];
    const sorted = [...versions].sort((a, b) => compareVersions(getContractVersion(b), getContractVersion(a)));

    logApp.debug('[OPENCTI-MODULE] Catalog persistence upserting contracts for slug', { slug, versionCount: sorted.length });
    for (let v = 0; v < sorted.length; v += 1) {
      const contract = sorted[v];
      const version = getContractVersion(contract);
      if (!version) {
        logApp.warn('[OPENCTI-MODULE] Catalog persistence skipping contract with empty version', { slug, title: contract.title });
        // Ignore malformed contracts instead of creating non-versioned records.
        continue;
      }

      const logo = contract.logo ?? '';
      const logoRef = logo ? computeLogoHash(logo) : undefined;
      if (logoRef && !seenLogoHashes.has(logoRef)) {
        await upsertCatalogLogo(context, user, {
          hash: logoRef,
          data_uri: logo,
          last_synced_at: now,
        });
        seenLogoHashes.add(logoRef);
      }

      await upsertCatalogContract(context, user, {
        slug,
        version,
        title: contract.title,
        description: contract.description ?? '',
        short_description: contract.short_description,
        logo_ref: logoRef,
        use_cases: contract.use_cases ?? [],
        verified: contract.verified ?? false,
        last_verified_date: contract.last_verified_date,
        playbook_supported: contract.playbook_supported ?? false,
        manager_supported: contract.manager_supported ?? false,
        subscription_link: contract.subscription_link,
        source_code: contract.source_code,
        type: getContractType(contract),
        config_schema: JSON.stringify(contract.config_schema ?? {}),
        image: getContractImage(contract),
        support_version: contract.support_version,
        max_confidence_level: contract.max_confidence_level,
        format_version: contract.format_version,
        is_latest: v === 0,
        last_synced_at: now,
      });
    }
  }

  const incomingContractKeys = new Set<string>(
    contracts
      .map((contract) => ({ slug: contract.slug, version: getContractVersion(contract) }))
      .filter((contract) => !!contract.version)
      .map((contract) => `${contract.slug}::${contract.version}`),
  );

  for (let i = 0; i < existingContracts.length; i += 1) {
    const existingContract = existingContracts[i];
    const contractKey = `${existingContract.slug}::${existingContract.version}`;
    if (!incomingContractKeys.has(contractKey)) {
      logApp.info('[OPENCTI-MODULE] Catalog persistence deleting missing contract', {
        slug: existingContract.slug,
        version: existingContract.version,
      });
      await deleteElementById(context, user, existingContract.id, ENTITY_TYPE_CATALOG_CONTRACT);
    }
  }

  // GC orphan logos (not referenced by any remaining or newly ingested contract).
  const allContractsAfterSync = await findAllCatalogContracts(context, user);
  const referencedLogoRefs = new Set<string>(
    allContractsAfterSync
      .map((contract) => (contract as unknown as Record<string, unknown>).logo_ref)
      .filter((ref): ref is string => typeof ref === 'string' && ref.length > 0),
  );
  const allLogos = await findAllCatalogLogos(context, user);
  for (let i = 0; i < allLogos.length; i += 1) {
    const logo = allLogos[i];
    if (!referencedLogoRefs.has(logo.hash)) {
      logApp.info('[OPENCTI-MODULE] Catalog persistence deleting unreferenced logo', { hash: logo.hash });
      await deleteElementById(context, user, logo.id, ENTITY_TYPE_CATALOG_LOGO);
    }
  }

  logApp.info('[OPENCTI-MODULE] Catalog persistence snapshot complete', { slugCount: bySlug.size });
};
