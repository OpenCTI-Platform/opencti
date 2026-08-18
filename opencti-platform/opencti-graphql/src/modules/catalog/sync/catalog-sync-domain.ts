import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import conf, { isFeatureEnabled, logApp, PLATFORM_VERSION } from '../../../config/conf';
import {
  deleteCatalogContracts,
  deleteCatalogs,
  findCatalogContractsByCatalogId,
  findCatalogManifestByCatalogId,
  findCatalogManifestBySourceUri,
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
import { fetchSourceCatalog, fetchSourceCatalogRevisionHint } from './catalog-sync-source-gateway';
import { generateStandardId, idGenFromData } from '../../../schema/identifier';
import { ENTITY_TYPE_CATALOG_CONTRACT, ENTITY_TYPE_CATALOG_MANIFEST } from '../catalog-types';
import { UnsupportedError } from '../../../config/errors';

const DECOUPLING_VERSIONS_FEATURE_FLAG = 'DECOUPLING_VERSIONS';

const getDecouplingRemoteUri = (): string | undefined => {
  const xtmHubUrl = conf.get('xtm:xtmhub_url');
  if (!isFeatureEnabled(DECOUPLING_VERSIONS_FEATURE_FLAG) || typeof xtmHubUrl !== 'string' || xtmHubUrl.length === 0) {
    return undefined;
  }
  const normalized = xtmHubUrl.endsWith('/') ? xtmHubUrl.slice(0, -1) : xtmHubUrl;
  return `${normalized}/opencti/${encodeURIComponent(PLATFORM_VERSION)}/connector/manifests/latest`;
};

const computeCatalogRevision = (rawManifest: unknown): string => {
  return createHash('sha256').update(JSON.stringify(rawManifest)).digest('hex');
};

const buildCatalogContractIds = (catalogId: string, contractId: string) => {
  const keyData = { catalog_id: catalogId, contract_id: contractId };
  return {
    internal_id: idGenFromData(ENTITY_TYPE_CATALOG_CONTRACT, keyData),
    standard_id: generateStandardId(ENTITY_TYPE_CATALOG_CONTRACT, keyData),
  };
};

const buildCatalogManifestIds = (catalogId: string) => {
  const keyData = { catalog_id: catalogId };
  return {
    internal_id: idGenFromData(ENTITY_TYPE_CATALOG_MANIFEST, keyData),
    standard_id: generateStandardId(ENTITY_TYPE_CATALOG_MANIFEST, keyData),
  };
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
      throw UnsupportedError(`Error while preparing logo for contract ${sourceContract.id}`, {
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
        throw UnsupportedError(`Missing logo upload operation for contract ${sourceContract.id}`);
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
      const ids = buildCatalogContractIds(params.sourceCatalog.id, sourceContract.id);
      const contractCreation: CatalogContractCreation = {
        ...ids,
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
        contract_version: sourceContract.container_version,
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
    const ids = buildCatalogContractIds(params.sourceCatalog.id, sourceContract.id);
    const contractUpdate: CatalogContractUpdate = {
      internal_id: currentContract.internal_id ?? currentContract.id,
      standard_id: ids.standard_id,
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
      contract_version: sourceContract.container_version,
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
  const catalogManifestIds = buildCatalogManifestIds(params.sourceCatalog.id);
  const catalogManifestUpsert: CatalogManifestUpsert = {
    ...catalogManifestIds,
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
    logApp.debug('[OPENCTI-MODULE] Synchronizing catalog', {
      sourceKind: sourceConfig.kind,
      sourceUri: sourceConfig.uri,
    });
    const currentCatalogBySourceUri = sourceConfig.kind === 'remote'
      ? await findCatalogManifestBySourceUri(context, user, sourceConfig.uri)
      : undefined;
    const remoteRevisionHint = sourceConfig.kind === 'remote'
      ? await fetchSourceCatalogRevisionHint(sourceConfig)
      : undefined;
    if (sourceConfig.kind === 'remote' && currentCatalogBySourceUri?.revision) {
      if (remoteRevisionHint && remoteRevisionHint === currentCatalogBySourceUri.revision) {
        logApp.info('[OPENCTI-MODULE] Catalog manager manifest unchanged (remote ETag match)', {
          sourceKind: sourceConfig.kind,
          catalogId: currentCatalogBySourceUri.catalog_id,
          revision: remoteRevisionHint,
          module: 'catalog',
        });
        return {
          synced: false,
          catalogId: currentCatalogBySourceUri.catalog_id,
        } as const;
      }
    }
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
    if (currentCatalogBySourceUri && currentCatalogBySourceUri.catalog_id !== sourceCatalog.id) {
      logApp.warn('[OPENCTI-MODULE] Same catalog source with different ID', {
        sourceKind: sourceConfig.kind,
        knownId: currentCatalogBySourceUri.catalog_id,
        newId: sourceCatalog.id,
        module: 'catalog',
      });
    }
    // Compute revision and compare with persisted, return early if equal.
    const revision = remoteRevisionHint ?? computeCatalogRevision(sourceCatalog);
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
      ? await findCatalogContractsByCatalogId(context, user, currentCatalog.catalog_id)
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
    // Something's fishy if this occurs too frequently.
    logApp.warn('[OPENCTI-MODULE] Persisting catalog & contracts', {
      catalogId: sourceCatalog.id,
      contractsCreationsCount: catalogSyncDiff.contractsCreations.length,
      contractsUpdatesCount: catalogSyncDiff.contractsUpdates.length,
      contractsDeletionsCount: catalogSyncDiff.contractsDeletions.length,
      module: 'catalog',
    });
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

const EMBEDDED_CATALOG_SYNC_SOURCE: CatalogSyncSourceConfig = { kind: 'embedded', uri: 'embedded' } as const;

const parseCustomCatalogEndpointUri = (uri: string): CatalogSyncSourceConfig => {
  if (uri.startsWith('http://') || uri.startsWith('https://')) {
    return { kind: 'remote', uri };
  }
  if (uri.startsWith('file://')) {
    const filepath = fileURLToPath(uri);
    return {
      kind: 'local',
      filepath,
      uri,
    };
  }
  throw UnsupportedError('Unsupported custom catalog endpoint URI protocol', {
    uri,
    supportedProtocols: ['file://', 'http://', 'https://'],
  });
};

const initSyncSources = () => {
  // Build catalog sources configs from env vars/app settings
  const sources: CatalogSyncSourceConfig[] = [];
  const decouplingRemoteUri = getDecouplingRemoteUri();
  if (decouplingRemoteUri) {
    sources.push({ kind: 'remote', uri: decouplingRemoteUri });
  } else {
    sources.push(EMBEDDED_CATALOG_SYNC_SOURCE);
  }
  const customCatalogRefreshEndpointUri = conf.get('catalog_manager:custom_catalog_refresh_endpoint_uri');
  if (typeof customCatalogRefreshEndpointUri === 'string' && customCatalogRefreshEndpointUri.length > 0) {
    sources.push(parseCustomCatalogEndpointUri(customCatalogRefreshEndpointUri));
  }
  const CUSTOM_CATALOGS: string[] = conf.get('app:custom_catalogs') ?? [];
  if (CUSTOM_CATALOGS) {
    sources.push(...CUSTOM_CATALOGS.map((customCatalog) => {
      if (customCatalog.startsWith('http://') || customCatalog.startsWith('https://')) {
        return {
          kind: 'remote' as const,
          uri: customCatalog,
        };
      }
      return {
        kind: 'local' as const,
        filepath: customCatalog,
        uri: pathToFileURL(customCatalog).toString(),
      };
    }));
  }
  return sources.filter((source, idx, all) => all.findIndex((candidate) => candidate.uri === source.uri) === idx);
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
  const decouplingRemoteUri = getDecouplingRemoteUri();
  logApp.debug('[OPENCTI-MODULE] Synchronizing catalogs', {
    count: sources.length,
    decouplingRemoteUri,
    module: 'catalog',
  });
  const syncedCatalogs: string[] = [];
  const syncedCatalogsWithChanges: string[] = [];
  // Sync catalogs from sources
  for (const source of sources) {
    let result = await synchronizeCatalog(context, user, source);
    if (source.kind === 'remote' && result.error && decouplingRemoteUri && source.uri === decouplingRemoteUri) {
      const alreadyPersistedRemoteCatalog = await findCatalogManifestBySourceUri(context, user, source.uri);
      if (!alreadyPersistedRemoteCatalog) {
        logApp.error('[OPENCTI-MODULE] Remote catalog source failed before first successful persistence, falling back to embedded source', {
          sourceKind: source.kind,
          sourceUri: source.uri,
          module: 'catalog',
        });
        result = await synchronizeCatalog(context, user, EMBEDDED_CATALOG_SYNC_SOURCE);
      }
    }
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
