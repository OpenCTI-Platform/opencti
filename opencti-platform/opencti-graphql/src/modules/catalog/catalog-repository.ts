import { PLATFORM_VERSION } from '../../config/conf';
import { elDeleteInstances, elIndex, elIndexElements, elLoadBy } from '../../database/engine';
import { fullEntitiesList } from '../../database/middleware-loader';
import { INDEX_INTERNAL_OBJECTS, READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { FilterMode, FilterOperator, OrderingMode } from '../../generated/graphql';
import type { BasicStoreBase } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import {
  type BasicStoreEntityCatalogContract,
  ENTITY_TYPE_CATALOG_CONTRACT,
  type BasicStoreEntityCatalog,
  type CatalogContractCreation,
  type CatalogContractUpdate,
  type CatalogContractDeletion,
  type CatalogUpsert,
  ENTITY_TYPE_CATALOG,
} from './catalog-types';

/**
 * Catalog data accessors & mutators
 */

export const findCatalogByCatalogId = async (
  context: AuthContext,
  user: AuthUser,
  catalogId: string,
) => {
  const catalog = await elLoadBy<BasicStoreEntityCatalog>(context, user, 'catalog_id', catalogId, ENTITY_TYPE_CATALOG);
  return catalog;
};

export const findCatalogBySourceUri = async (
  context: AuthContext,
  user: AuthUser,
  sourceUri: string,
) => {
  const catalog = await elLoadBy<BasicStoreEntityCatalog>(context, user, 'source_uri', sourceUri);
  return catalog;
};

export const upsertCatalog = async (_context: AuthContext, _user: AuthUser, update: CatalogUpsert) => {
  await elIndex(INDEX_INTERNAL_OBJECTS, {
    ...update,
    entity_type: ENTITY_TYPE_CATALOG,
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
  const catalogs = await fullEntitiesList<BasicStoreEntityCatalog>(
    context,
    user,
    [ENTITY_TYPE_CATALOG],
    { indices: [READ_INDEX_INTERNAL_OBJECTS], filters },
  );
  return catalogs;
};

export const deleteCatalogs = async (context: AuthContext, catalogEntities: BasicStoreEntityCatalog[]) => {
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
      indices: [READ_INDEX_INTERNAL_OBJECTS],
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
  return contracts.reduce((map, contract) => {
    map.set(contract.contract_id, contract);
    return map;
  }, new Map<string, BasicStoreEntityCatalogContract>());
};

export const findLatestCompatibleCatalogContractsByCatalogId = async (
  context: AuthContext,
  user: AuthUser,
  catalogId: string,
) => {
  const contracts = await fullEntitiesList<BasicStoreEntityCatalogContract>(
    context,
    user,
    [ENTITY_TYPE_CATALOG_CONTRACT],
    {
      indices: [READ_INDEX_INTERNAL_OBJECTS],
      filters: {
        filters: [{
          key: ['catalog_id'],
          values: [catalogId],
        }],
        filterGroups: [
          {
            mode: FilterMode.Or,
            filters: [],
            filterGroups: [
              {
                mode: FilterMode.And,
                filters: [{
                  key: ['support_version'],
                  values: [PLATFORM_VERSION],
                  operator: FilterOperator.Lte,
                }],
                filterGroups: [],
              },
              {
                mode: FilterMode.And,
                filters: [{
                  key: ['support_version'],
                  values: ['EXISTS'],
                  operator: FilterOperator.NotEq,
                }],
                filterGroups: [],
              },
            ],
          },
        ],
        mode: FilterMode.And,
      },
      orderBy: 'contract_version',
      orderMode: OrderingMode.Desc,
    },
  );
  // Keep latest compatible version by slug (results are sorted by version desc).
  return contracts.reduce((map, contract) => {
    if (map.has(contract.slug)) {
      return map;
    }
    map.set(contract.slug, contract);
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
      indices: [READ_INDEX_INTERNAL_OBJECTS],
      filters: {
        filters: [{
          key: ['slug'],
          values: [contractSlug],
        }],
        filterGroups: [
          {
            mode: FilterMode.Or,
            filters: [],
            filterGroups: [
              {
                mode: FilterMode.And,
                filters: [{
                  key: ['support_version'],
                  values: [PLATFORM_VERSION],
                  operator: FilterOperator.Lte,
                }],
                filterGroups: [],
              },
              {
                mode: FilterMode.And,
                filters: [{
                  key: ['support_version'],
                  values: ['EXISTS'],
                  operator: FilterOperator.NotEq,
                }],
                filterGroups: [],
              },
            ],
          },
        ],
        mode: FilterMode.And,
      },
      orderBy: 'contract_version',
      orderMode: OrderingMode.Desc,
      first: 1,
    },
  );
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
      indices: [READ_INDEX_INTERNAL_OBJECTS],
      filters: {
        filters: [{
          key: ['image'],
          values: [imageName],
        }],
        filterGroups: [
          {
            mode: FilterMode.Or,
            filters: [],
            filterGroups: [
              {
                mode: FilterMode.And,
                filters: [{
                  key: ['support_version'],
                  values: [PLATFORM_VERSION],
                  operator: FilterOperator.Lte,
                }],
                filterGroups: [],
              },
              {
                mode: FilterMode.And,
                filters: [{
                  key: ['support_version'],
                  values: ['EXISTS'],
                  operator: FilterOperator.NotEq,
                }],
                filterGroups: [],
              },
            ],
          },
        ],
        mode: FilterMode.And,
      },
      orderBy: 'contract_version',
      orderMode: OrderingMode.Desc,
      first: 1,
    },
  );
  return contracts[0];
};

export const insertCatalogContracts = async (
  context: AuthContext,
  user: AuthUser,
  contracts: CatalogContractCreation[],
) => {
  const contractsToIndex = contracts.map((contract) => ({
    ...contract,
    _index: INDEX_INTERNAL_OBJECTS,
    entity_type: ENTITY_TYPE_CATALOG_CONTRACT,
  }));
  await elIndexElements(context, user, ENTITY_TYPE_CATALOG_CONTRACT, contractsToIndex);
};

export const updateCatalogContracts = async (
  context: AuthContext,
  user: AuthUser,
  updates: CatalogContractUpdate[],
) => {
  // We can use bulk `index` as we provide the entire documents
  const contractsToIndex = updates.map((update) => ({
    ...update,
    _index: INDEX_INTERNAL_OBJECTS,
    entity_type: ENTITY_TYPE_CATALOG_CONTRACT,
  }));
  await elIndexElements(context, user, ENTITY_TYPE_CATALOG_CONTRACT, contractsToIndex);
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
