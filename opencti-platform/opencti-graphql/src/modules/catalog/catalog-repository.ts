import { elDeleteInstances, elIndex, elIndexElements, elLoadBy } from '../../database/engine';
import { fullEntitiesList } from '../../database/middleware-loader';
import { INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import type { BasicStoreBase } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import {
  type BasicStoreEntityCatalogContract,
  ENTITY_TYPE_CATALOG_CONTRACT,
  type BasicStoreEntityCatalogManifest,
  type CatalogContractCreation,
  type CatalogContractUpdate,
  type CatalogContractDeletion,
  type CatalogManifestUpsert,
  ENTITY_TYPE_CATALOG_MANIFEST,
} from './catalog-types';

/**
 * Catalog data accessors & mutators
 */

export const findCatalogManifestByCatalogId = async (
  context: AuthContext,
  user: AuthUser,
  catalogId: string,
) => {
  const catalog = await elLoadBy<BasicStoreEntityCatalogManifest>(context, user, 'catalog_id', catalogId);
  return catalog;
};

export const upsertCatalog = async (_context: AuthContext, _user: AuthUser, update: CatalogManifestUpsert) => {
  await elIndex(INDEX_INTERNAL_OBJECTS, {
    ...update,
    entity_type: ENTITY_TYPE_CATALOG_MANIFEST,
  });
};

export const findCatalogs = async (context: AuthContext, user: AuthUser, excludedIds?: string[]) => {
  const filters = excludedIds?.length ? {
    filters: [{
      key: ['catalog_id'],
      values: excludedIds,
      operator: FilterOperator.NotEq,
    }],
    filterGroups: [],
    mode: FilterMode.And,
  } : null;
  const catalogs = await fullEntitiesList<BasicStoreEntityCatalogManifest>(
    context,
    user,
    [ENTITY_TYPE_CATALOG_MANIFEST],
    { filters },
  );
  return catalogs;
};

export const deleteCatalogs = async (context: AuthContext, catalogEntities: BasicStoreEntityCatalogManifest[]) => {
  await elDeleteInstances(context, catalogEntities);
};

/**
 * Catalog contracts data accessors & mutators
 */

export const findCatalogContractsByCatalogId = async (
  context: AuthContext,
  user: AuthUser,
  catalogId: string,
) => {
  const contracts = await fullEntitiesList<BasicStoreEntityCatalogContract>(
    context,
    user,
    [ENTITY_TYPE_CATALOG_CONTRACT],
    {
      filters: {
        filters: [{
          key: ['catalog_id'],
          values: [catalogId],
        }],
        filterGroups: [],
        mode: FilterMode.And,
      },
    },
  );
  // TODO: check if filter with support_version
  return contracts.reduce((map, contract) => {
    map.set(contract.contract_id, contract);
    return map;
  }, new Map<string, BasicStoreEntityCatalogContract>());
};

export const findLatestCompatibleCatalogContractBySlug = async (
  context: AuthContext,
  user: AuthUser,
  contractSlug: string,
) => {
  const contracts = await fullEntitiesList<BasicStoreEntityCatalogContract>(
    context,
    user,
    [ENTITY_TYPE_CATALOG_CONTRACT],
    {
      filters: {
        filters: [{
          key: ['slug'],
          values: [contractSlug],
        }],
        filterGroups: [],
        mode: FilterMode.And,
      },
    },
  );
  // Filter with support_version
  // Sort by version DESC
  return contracts[0];
};

export const findLatestCompatibleCatalogContractByImageName = async (
  context: AuthContext,
  user: AuthUser,
  imageName: string,
) => {
  const contracts = await fullEntitiesList<BasicStoreEntityCatalogContract>(
    context,
    user,
    [ENTITY_TYPE_CATALOG_CONTRACT],
    {
      filters: {
        filters: [{
          key: ['image'],
          values: [imageName],
        }],
        filterGroups: [],
        mode: FilterMode.And,
      },
    },
  );
  // Filter with support_version
  // Sort by version DESC
  return contracts[0];
};

export const insertCatalogContracts = async (
  context: AuthContext,
  user: AuthUser,
  contracts: CatalogContractCreation[],
) => {
  await elIndexElements(context, user, ENTITY_TYPE_CATALOG_CONTRACT, contracts);
};

export const updateCatalogContracts = async (
  context: AuthContext,
  user: AuthUser,
  updates: CatalogContractUpdate[],
) => {
  // We can use bulk `index` as we provide the entire documents
  await elIndexElements(context, user, ENTITY_TYPE_CATALOG_CONTRACT, updates);
};

export const deleteCatalogContracts = async (
  context: AuthContext,
  _user: AuthUser,
  deletions: CatalogContractDeletion[],
) => {
  const docs = deletions.map((deletion) => ({
    _index: INDEX_INTERNAL_OBJECTS,
    _id: deletion.idToDelete,
  } as BasicStoreBase));
  await elDeleteInstances(context, docs);
};
