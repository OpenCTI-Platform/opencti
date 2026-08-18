import { createHash } from 'node:crypto';
import conf, { logApp } from '../../../config/conf';
import {
  deleteCatalogContracts,
  deleteCatalogs,
  findCatalogContractsByCatalogId,
  findCatalogManifestByCatalogId,
  findCatalogs,
  insertCatalogContracts,
  updateCatalogContracts,
  upsertCatalog,
} from '../catalog-repository';
import { SYSTEM_USER } from '../../../utils/access';
import type { AuthContext, AuthUser } from '../../../types/user';
import {
  type CatalogContractLogoUploadOperation,
  computeCatalogContractLogoUploadOperation,
  listCatalogContractLogos,
  uploadCatalogContractLogoOperation,
} from '../catalog-logo-storage';
import type {
  BasicStoreEntityCatalogContract,
  BasicStoreEntityCatalogManifest,
  CatalogContractCreation,
  CatalogContractDeletion,
  CatalogContractUpdate,
  CatalogManifestUpsert,
} from '../catalog-types';
import type { CatalogContractSyncSource, CatalogSyncSource, CatalogSyncSourceConfig } from './catalog-sync-types';
import { fetchSourceCatalog } from './catalog-sync-source-gateway';

const computeCatalogRevision = (rawManifest: unknown): string => {
  return createHash('sha256').update(JSON.stringify(rawManifest)).digest('hex');
};

export const computeContractContentHash = (contract: CatalogContractSyncSource) => {
  const replacer = (_key: string, value: Record<string, unknown>) =>
    value && typeof value === 'object' && !Array.isArray(value)
      ? Object.keys(value).sort().reduce((sorted, k) => {
          sorted[k] = value[k];
          return sorted;
        }, {} as Record<string, unknown>)
      : value;
  return createHash('sha256').update(JSON.stringify(contract, replacer)).digest('hex');
};

const computeCatalogLogosSyncOps = (
  sourceCatalog: CatalogSyncSource,
  currentLogos: Set<string>,
) => {
  const plannedLogos = new Set(currentLogos);
  const sourceCatalogLogosUris = new Map<string, string>();
  const uploadOperations: CatalogContractLogoUploadOperation[] = [];
  for (const sourceContract of sourceCatalog.contracts) {
    const logoOperationResult = computeCatalogContractLogoUploadOperation(sourceContract, plannedLogos);
    if (logoOperationResult.result === 'failed') {
      throw new Error(`Error while preparing logo for contract ${sourceContract.id}`, {
        cause: logoOperationResult.error,
      });
    }
    if (logoOperationResult.result === 'no-logo') {
      continue;
    }
    sourceCatalogLogosUris.set(sourceContract.id, logoOperationResult.logoUri);
    plannedLogos.add(logoOperationResult.filename);
    if (!logoOperationResult.existed) {
      if (!logoOperationResult.operation) {
        throw new Error(`Missing logo upload operation for contract ${sourceContract.id}`);
      }
      uploadOperations.push(logoOperationResult.operation);
    }
  }
  return {
    sourceCatalogLogosUris,
    uploadOperations,
  };
};

const uploadCatalogContractLogos = async (operations: CatalogContractLogoUploadOperation[]) => {
  for (const operation of operations) {
    const uploadResult = await uploadCatalogContractLogoOperation(operation);
    if (uploadResult.result === 'failed') {
      throw uploadResult.error;
    }
  }
};

const computeCatalogSyncOps = (params: {
  revision: string;
  sourceConfig: CatalogSyncSourceConfig;
  sourceCatalog: CatalogSyncSource;
  sourceCatalogContractsHashes: Map<string, string>;
  sourceCatalogLogosUris: Map<string, string>;
  currentCatalog: BasicStoreEntityCatalogManifest | undefined;
  currentContracts: Map<string, BasicStoreEntityCatalogContract>;
}) => {
  const sourceContractsIds = new Set(params.sourceCatalogContractsHashes.keys());
  const contractsCreations: CatalogContractCreation[] = [];
  const contractsUpdates: CatalogContractUpdate[] = [];
  const contractsDeletions: CatalogContractDeletion[] = [];

  params.sourceCatalog.contracts.forEach((sourceContract) => {
    const sourceContractHash = params.sourceCatalogContractsHashes.get(sourceContract.id)!;
    const currentContract = params.currentContracts.get(sourceContract.id);
    if (!currentContract) {
      const contractCreation: CatalogContractCreation = {
        catalog_id: params.sourceCatalog.id,
        contract_id: sourceContract.id,
        content_hash: sourceContractHash,
        title: sourceContract.title,
        slug: sourceContract.slug,
        description: sourceContract.description,
        short_description: sourceContract.short_description,
        logo_uri: params.sourceCatalogLogosUris.get(sourceContract.id) ?? undefined,
        use_cases: [...sourceContract.use_cases],
        verified: sourceContract.verified,
        last_verified_date: sourceContract.last_verified_date ?? undefined,
        playbook_supported: sourceContract.playbook_supported,
        max_confidence_level: sourceContract.max_confidence_level,
        support_version: sourceContract.support_version ?? undefined,
        subscription_link: sourceContract.subscription_link ?? undefined,
        source_code: sourceContract.source_code ?? undefined,
        manager_supported: sourceContract.manager_supported,
        version: sourceContract.container_version,
        image: sourceContract.container_image,
        connector_type: sourceContract.container_type,
        config_schema: sourceContract.config_schema,
        license_type: sourceContract.license_type ?? undefined,
        solution_categories: sourceContract.solution_categories,
        contact: sourceContract.contact ?? undefined,
      };
      contractsCreations.push(contractCreation);
      return;
    }
    if (sourceContractHash === currentContract.content_hash) {
      return;
    }
    const contractUpdate: CatalogContractUpdate = {
      catalog_id: params.sourceCatalog.id,
      contract_id: sourceContract.id,
      content_hash: sourceContractHash,
      title: sourceContract.title,
      slug: sourceContract.slug,
      description: sourceContract.description,
      short_description: sourceContract.short_description,
      logo_uri: params.sourceCatalogLogosUris.get(sourceContract.id) ?? null,
      use_cases: [...sourceContract.use_cases],
      verified: sourceContract.verified,
      last_verified_date: sourceContract.last_verified_date,
      playbook_supported: sourceContract.playbook_supported,
      max_confidence_level: sourceContract.max_confidence_level,
      support_version: sourceContract.support_version,
      subscription_link: sourceContract.subscription_link,
      manager_supported: sourceContract.manager_supported,
      version: sourceContract.container_version,
      image: sourceContract.container_image,
      connector_type: sourceContract.container_type,
      config_schema: sourceContract.config_schema,
      solution_categories: sourceContract.solution_categories,
      source_code: sourceContract.source_code,
      license_type: sourceContract.license_type,
      contact: sourceContract.contact,
    };
    contractsUpdates.push(contractUpdate);
  });

  params.currentContracts.forEach((currentContract) => {
    if (!sourceContractsIds.has(currentContract.contract_id)) {
      contractsDeletions.push({ idToDelete: currentContract.id });
      return;
    }
  });
  const catalogManifestUpsert: CatalogManifestUpsert = {
    revision: params.revision,
    source_uri: params.sourceConfig.uri,
    catalog_id: params.sourceCatalog.id,
    name: params.sourceCatalog.name,
    description: params.sourceCatalog.description,
    version: params.sourceCatalog.version,
  };
  return {
    contractsCreations,
    contractsUpdates,
    contractsDeletions,
    catalogManifestUpsert,
  };
};

const synchronizeCatalog = async (context: AuthContext, user: AuthUser, sourceConfig: CatalogSyncSourceConfig) => {
  try {
    // Fetch source catalog
    const sourceCatalog = await fetchSourceCatalog(sourceConfig);
    // Find existing persisted data in the database corresponding to the catalog id
    const currentCatalog = await findCatalogManifestByCatalogId(context, user, sourceCatalog.id);
    const currentRevision = currentCatalog?.revision;
    if (currentCatalog) {
      logApp.debug('[OPENCTI-MODULE] Found existing persisted catalog', {
        sourceKind: sourceConfig.kind,
        catalogId: currentCatalog.catalog_id,
        revision: currentRevision,
        module: 'catalog',
      });
    } else {
      logApp.debug('[OPENCTI-MODULE] New catalog source', {
        sourceKind: sourceConfig.kind,
        module: 'catalog',
      });
    }
    if (currentCatalog && currentCatalog.id !== sourceCatalog.id) {
      logApp.warn('[OPENCTI-MODULE] Same catalog source with different ID', {
        sourceKind: sourceConfig.kind,
        knownId: currentCatalog.id,
        newId: sourceCatalog.id,
        module: 'catalog',
      });
    }
    // Compute revision and compare with persisted, return early if equal.
    const revision = computeCatalogRevision(sourceCatalog);
    if (currentRevision && revision === currentRevision) {
      logApp.info('[OPENCTI-MODULE] Catalog manager manifest unchanged (revision match)', {
        sourceKind: sourceConfig.kind,
        catalogId: sourceCatalog.id,
        revision,
        module: 'catalog',
      });
      return {
        synced: false,
        catalogId: sourceCatalog.id,
      } as const;
    }
    // Fetch all current contracts, logos & compute sync diff
    const currentContracts = currentCatalog
      ? await findCatalogContractsByCatalogId(context, user, currentCatalog.id)
      : new Map<string, BasicStoreEntityCatalogContract>();
    const currentLogos = await listCatalogContractLogos();
    const logoSyncOps = computeCatalogLogosSyncOps(sourceCatalog, currentLogos);
    const sourceCatalogContractsHashes = sourceCatalog.contracts.reduce((hashesMap, contract) => {
      hashesMap.set(contract.id, computeContractContentHash(contract));
      return hashesMap;
    }, new Map<string, string>());
    const catalogSyncDiff = computeCatalogSyncOps({
      revision,
      sourceConfig,
      sourceCatalog,
      sourceCatalogContractsHashes,
      sourceCatalogLogosUris: logoSyncOps.sourceCatalogLogosUris,
      currentCatalog,
      currentContracts,
    });
    // Persist refreshed catalog, contracts & logos
    await uploadCatalogContractLogos(logoSyncOps.uploadOperations);
    await insertCatalogContracts(context, user, catalogSyncDiff.contractsCreations);
    if (catalogSyncDiff.contractsUpdates.length > 0) {
      // Usually there would be no updates of catalog contracts given a change
      // would be treated in a new version. This could be the result of a previous
      // failure being compensated or an issue in the release process.
      // Something's fishy if this occurs too frequently.
      logApp.warn('[OPENCTI-MODULE] Catalog contracts updates', {
        catalogId: sourceCatalog.id,
        count: catalogSyncDiff.contractsUpdates.length,
        module: 'catalog',
      });
      await updateCatalogContracts(context, user, catalogSyncDiff.contractsUpdates);
    }
    await deleteCatalogContracts(context, user, catalogSyncDiff.contractsDeletions);
    await upsertCatalog(context, user, catalogSyncDiff.catalogManifestUpsert);
    const isNotNil = (str: string | null | undefined): str is string => Boolean(str);
    let usedLogos = catalogSyncDiff.contractsCreations.map(({ logo_uri }) => logo_uri).filter(isNotNil);
    usedLogos = usedLogos.concat(catalogSyncDiff.contractsUpdates.map(({ logo_uri }) => logo_uri).filter(isNotNil));
    return {
      synced: true as const,
      catalogId: sourceCatalog.id,
      usedLogos: new Set(usedLogos),
    };
  } catch (exception) {
    logApp.error('[OPENCTI-MODULE] [catalog] Error while syncing catalog', {
      cause: exception,
    });
    return { synced: false, error: true } as const;
  }
};

const initSyncSources = () => {
  // Build catalog sources configs from env vars/app settings
  const sources: CatalogSyncSourceConfig[] = [{
    kind: 'embedded' as const,
    uri: 'embedded',
  }];
  const CUSTOM_CATALOGS: string[] = conf.get('app:custom_catalogs') ?? [];
  if (CUSTOM_CATALOGS) {
    sources.push(...CUSTOM_CATALOGS.map((customCatalog) => ({
      kind: 'local' as const,
      filepath: customCatalog,
      uri: 'file:///' + customCatalog, // TODO: normalize
    })));
  }
  return sources;
};

const cleanupObsoleteCatalogs = async (context: AuthContext, syncedCatalogs: string[]) => {
  const obsoleteCatalogs = await findCatalogs(context, SYSTEM_USER, syncedCatalogs);
  if (obsoleteCatalogs.length) {
    // The app config changed resulting in a catalog not being synced anymore
    logApp.warn('[OPENCTI-MODULE] Deleting obsolete catalogs', {
      module: 'catalog',
      deletedCatalogIds: obsoleteCatalogs.map((catalog) => catalog.catalog_id),
    });
    await deleteCatalogs(context, obsoleteCatalogs);
  }
};

export const synchronizeCatalogs = async (context: AuthContext, user: AuthUser) => {
  const sources = initSyncSources();
  logApp.debug('[OPENCTI-MODULE] Synchronizing catalogs', {
    count: sources.length,
    module: 'catalog',
  });
  const syncedCatalogs: string[] = [];
  const syncedCatalogsWithChanges: string[] = [];
  // Sync catalogs from sources
  for (const source of sources) {
    const result = await synchronizeCatalog(context, user, source);
    if (!result.error) {
      syncedCatalogs.push(result.catalogId);
      if (result.synced) {
        syncedCatalogsWithChanges.push(result.catalogId);
      }
    }
  };
  // Cleanup obsolete catalogs only if no sync failed
  if (syncedCatalogs.length === sources.length) {
    await cleanupObsoleteCatalogs(context, syncedCatalogs);
  }
  return syncedCatalogsWithChanges;
};
