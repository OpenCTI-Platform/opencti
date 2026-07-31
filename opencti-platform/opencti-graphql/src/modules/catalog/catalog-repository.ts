// opencti-platform/opencti-graphql/src/modules/catalog/catalog-persistence.ts

import { createHash } from 'node:crypto';
import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, deleteElementById } from '../../database/middleware';
import { fullEntitiesList } from '../../database/middleware-loader';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { ENTITY_TYPE_CATALOG_CONTRACT, ENTITY_TYPE_CATALOG_LOGO, ENTITY_TYPE_CATALOG_MANIFEST } from './catalog-entity-types';
import type { GraphqlCatalog } from './catalog-types';
import { sanitizeManagerConfigSchema } from './catalog-config-schema';

import type { BasicStoreEntityCatalogContract, BasicStoreEntityCatalogLogo, BasicStoreEntityCatalogManifest } from './catalog-entity';

export interface CatalogContractInput {
  catalog_id: string;
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
  last_synced_at: string;
}

export interface CatalogLogoInput {
  hash: string;
  data_uri: string;
  last_synced_at: string;
}

export interface CatalogManifestInput {
  source_uri: string;
  catalog_id: string;
  revision: string;
  manifest_version?: string;
  version?: string;
}

// -- Writes --

export const upsertCatalogContract = async (
  context: AuthContext,
  user: AuthUser,
  input: CatalogContractInput,
): Promise<BasicStoreEntityCatalogContract> => {
  logApp.debug('[OPENCTI-MODULE] Catalog persistence upserting CatalogContract', {
    catalogId: input.catalog_id,
    slug: input.slug,
    version: input.version,
  });
  const result = await createEntity(context, user, input, ENTITY_TYPE_CATALOG_CONTRACT);
  logApp.debug('[OPENCTI-MODULE] Catalog persistence upserted CatalogContract', {
    catalogId: input.catalog_id,
    slug: input.slug,
    version: input.version,
    id: result.id,
  });
  return result;
};

export const upsertCatalogLogo = async (
  context: AuthContext,
  user: AuthUser,
  input: CatalogLogoInput,
): Promise<BasicStoreEntityCatalogLogo> => {
  return createEntity(context, user, input, ENTITY_TYPE_CATALOG_LOGO);
};

export const upsertCatalogManifest = async (
  context: AuthContext,
  user: AuthUser,
  input: CatalogManifestInput,
): Promise<BasicStoreEntityCatalogManifest> => {
  logApp.debug('[OPENCTI-MODULE] Catalog persistence upserting CatalogManifest', {
    sourceUri: input.source_uri,
    catalogId: input.catalog_id,
    revision: input.revision,
  });
  const result = await createEntity(context, user, input, ENTITY_TYPE_CATALOG_MANIFEST);
  logApp.debug('[OPENCTI-MODULE] Catalog persistence upserted CatalogManifest', {
    sourceUri: result.source_uri,
    catalogId: result.catalog_id,
    revision: result.revision,
    id: result.id,
  });
  return result;
};

// -- Reads --

export const findLatestContractsBySlug = async (
  context: AuthContext,
  user: AuthUser,
): Promise<BasicStoreEntityCatalogContract[]> => {
  const contracts = await findAllCatalogContracts(context, user);
  const latestBySlug = new Map<string, BasicStoreEntityCatalogContract>();
  for (let i = 0; i < contracts.length; i += 1) {
    const contract = contracts[i];
    const current = latestBySlug.get(contract.slug);
    if (!current || compareVersions(contract.version, current.version) > 0) {
      latestBySlug.set(contract.slug, contract);
    }
  }
  return Array.from(latestBySlug.values());
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

export const findCatalogManifestBySourceUri = async (
  context: AuthContext,
  user: AuthUser,
  sourceUri: string,
): Promise<BasicStoreEntityCatalogManifest | undefined> => {
  const results = await fullEntitiesList<BasicStoreEntityCatalogManifest>(context, user, [ENTITY_TYPE_CATALOG_MANIFEST], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['source_uri'], values: [sourceUri], operator: FilterOperator.Eq }],
      filterGroups: [],
    },
  });
  const manifest = results[0];
  if (manifest) {
    logApp.debug('[OPENCTI-MODULE] Catalog persistence found CatalogManifest by source URI', {
      sourceUri,
      catalogId: manifest.catalog_id,
      revision: manifest.revision,
      id: manifest.id,
    });
  } else {
    logApp.debug('[OPENCTI-MODULE] Catalog persistence found no CatalogManifest by source URI', { sourceUri });
  }
  return manifest;
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
      ],
      filterGroups: [],
    },
  });
  if (results.length === 0) {
    return undefined;
  }
  return results.sort((a, b) => compareVersions(b.version, a.version))[0];
};

export const findLatestContractByContainerImage = async (
  context: AuthContext,
  user: AuthUser,
  containerImage: string,
): Promise<BasicStoreEntityCatalogContract | undefined> => {
  const results = await fullEntitiesList<BasicStoreEntityCatalogContract>(context, user, [ENTITY_TYPE_CATALOG_CONTRACT], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['image'], values: [containerImage], operator: FilterOperator.Eq },
      ],
      filterGroups: [],
    },
  });
  if (results.length === 0) {
    return undefined;
  }
  return results.sort((a, b) => compareVersions(b.version, a.version))[0];
};

export const findCatalogLogoByRef = async (
  context: AuthContext,
  user: AuthUser,
  ref: string,
): Promise<BasicStoreEntityCatalogLogo | undefined> => {
  const results = await fullEntitiesList<BasicStoreEntityCatalogLogo>(context, user, [ENTITY_TYPE_CATALOG_LOGO], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['hash'], values: [ref], operator: FilterOperator.Eq }],
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
}

export interface AdapterInternalCatalog {
  catalogId: string;
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

// Persists one fetched manifest snapshot and keeps one CatalogContract per
// (slug, version). Highest version selection is computed at read-time.
//
export const persistCatalogSnapshot = async (
  context: AuthContext,
  user: AuthUser,
  internalCatalog: AdapterInternalCatalog,
): Promise<void> => {
  const { catalogId } = internalCatalog;
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
    for (const contract of sorted) {
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

      const rawSchema = (contract as unknown as Record<string, unknown>).config_schema;
      const parsedSchema = typeof rawSchema === 'string' ? JSON.parse(rawSchema) : (rawSchema ?? {});
      const configSchema = sanitizeManagerConfigSchema(parsedSchema);

      await upsertCatalogContract(context, user, {
        catalog_id: catalogId,
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
        config_schema: JSON.stringify(configSchema),
        image: getContractImage(contract),
        support_version: contract.support_version,
        max_confidence_level: contract.max_confidence_level,
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

const buildContractStringFromES = (
  contract: BasicStoreEntityCatalogContract,
  logoByRef: Map<string, string>,
): string => {
  const rawSchema = (contract as unknown as Record<string, unknown>).config_schema;
  const rawLogoRef = (contract as unknown as Record<string, unknown>).logo_ref;
  const logoRef = typeof rawLogoRef === 'string' ? rawLogoRef : undefined;
  const resolvedLogo = (logoRef ? logoByRef.get(logoRef) : undefined) ?? contract.logo ?? '';
  const parsedSchema = typeof rawSchema === 'string' ? JSON.parse(rawSchema) : (rawSchema ?? {});
  const configSchema = sanitizeManagerConfigSchema(parsedSchema);

  return JSON.stringify({
    title: contract.title,
    slug: contract.slug,
    description: contract.description ?? '',
    short_description: contract.short_description ?? '',
    logo: resolvedLogo,
    use_cases: contract.use_cases ?? [],
    verified: contract.verified ?? false,
    last_verified_date: contract.last_verified_date ?? '',
    playbook_supported: contract.playbook_supported ?? false,
    manager_supported: contract.manager_supported ?? false,
    subscription_link: contract.subscription_link ?? '',
    source_code: contract.source_code ?? '',
    container_version: contract.version,
    container_image: (contract as unknown as Record<string, unknown>).image ?? '',
    container_type: contract.type ?? 'EXTERNAL_IMPORT',
    support_version: (contract as unknown as Record<string, unknown>).support_version ?? '',
    max_confidence_level: (contract as unknown as Record<string, unknown>).max_confidence_level ?? 100,
    config_schema: configSchema,
  });
};

const buildContractLookupResultFromES = async (
  context: AuthContext,
  user: AuthUser,
  contract: BasicStoreEntityCatalogContract,
): Promise<{ catalog_id: string; contract: string }> => {
  const logoRef = contract?.logo_ref && contract?.logo_ref?.length > 0 ? contract.logo_ref : undefined;

  const logoByRef = new Map<string, string>();
  if (logoRef) {
    const logo = await findCatalogLogoByRef(context, user, logoRef);
    if (logo) {
      logoByRef.set(logo.hash, logo.data_uri);
    }
  }

  return {
    catalog_id: contract.catalog_id,
    contract: buildContractStringFromES(contract, logoByRef),
  };
};

export const findContractFromESBySlug = async (
  context: AuthContext,
  user: AuthUser,
  slug: string,
): Promise<{ catalog_id: string; contract: string } | null> => {
  const contract = await findLatestContractBySlug(context, user, slug);
  if (!contract) {
    return null;
  }
  return buildContractLookupResultFromES(context, user, contract);
};

export const findContractFromESByContainerImage = async (
  context: AuthContext,
  user: AuthUser,
  containerImage: string,
): Promise<{ catalog_id: string; contract: string } | null> => {
  const contract = await findLatestContractByContainerImage(context, user, containerImage);
  if (!contract) {
    return null;
  }
  return buildContractLookupResultFromES(context, user, contract);
};

export const findCatalogFromES = async (
  context: AuthContext,
  user: AuthUser,
): Promise<GraphqlCatalog[]> => {
  const latestContracts = await findLatestContractsBySlug(context, user);
  const logoRefs = Array.from(new Set(
    latestContracts
      .map((contract) => (contract as unknown as Record<string, unknown>).logo_ref)
      .filter((ref): ref is string => typeof ref === 'string' && ref.length > 0),
  ));

  const logoByRef = new Map<string, string>();
  if (logoRefs.length > 0) {
    const logos = await findCatalogLogosByRefs(context, user, logoRefs);
    logos.forEach((logo) => {
      logoByRef.set(logo.hash, logo.data_uri);
    });
  }

  return latestContracts.map((contract) => ({
    id: contract.id,
    entity_type: contract.entity_type,
    parent_types: contract.parent_types,
    standard_id: contract.standard_id,
    name: contract.title,
    description: contract.description ?? '',
    contracts: [buildContractStringFromES(contract, logoByRef)],
  }));
};
