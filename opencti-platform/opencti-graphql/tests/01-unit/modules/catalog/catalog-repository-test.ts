import { beforeEach, describe, expect, it, vi } from 'vitest';
import { elDeleteInstances, elIndex, elIndexElements } from '../../../../src/database/engine';
import { fullEntitiesList, internalFindByIdsMapped } from '../../../../src/database/middleware-loader';
import { deleteCatalogContracts, findAllCatalogs, findAllCatalogsExcluding, updateCatalogContracts, upsertCatalog } from '../../../../src/modules/catalog/catalog-repository';
import {
  type BasicStoreEntityCatalog,
  type BasicStoreEntityCatalogContract,
  type CatalogContractUpdate,
  type CatalogUpsert,
  ENTITY_TYPE_CATALOG,
  ENTITY_TYPE_CATALOG_CONTRACT,
} from '../../../../src/modules/catalog/catalog-types';
import { INDEX_INTERNAL_OBJECTS, READ_INDEX_INTERNAL_OBJECTS } from '../../../../src/database/utils';
import { FilterMode, FilterOperator } from '../../../../src/generated/graphql';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/engine', () => ({
  elDeleteInstances: vi.fn(),
  elIndex: vi.fn(),
  elIndexElements: vi.fn(),
  elLoadBy: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
  internalFindByIdsMapped: vi.fn(),
}));

const context = {} as AuthContext;
const user = {} as AuthUser;
const contractId = 'catalog-contract--1';
const physicalIndex = 'opencti_internal_objects-000042';
const existingContract = {
  id: contractId,
  internal_id: contractId,
  _id: contractId,
  _index: physicalIndex,
  entity_type: ENTITY_TYPE_CATALOG_CONTRACT,
} as BasicStoreEntityCatalogContract;

describe('catalog repository', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(internalFindByIdsMapped).mockResolvedValue({
      [contractId]: existingContract,
    });
  });

  it('should find all catalogs without filters', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([]);

    await findAllCatalogs(context, user);

    expect(fullEntitiesList).toHaveBeenCalledWith(
      context,
      user,
      [ENTITY_TYPE_CATALOG],
      {
        indices: [READ_INDEX_INTERNAL_OBJECTS],
        filters: null,
      },
    );
  });

  it('should find catalogs excluding the specified catalog ids', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([]);

    await findAllCatalogsExcluding(context, user, ['catalog-1', 'catalog-2']);

    expect(fullEntitiesList).toHaveBeenCalledWith(
      context,
      user,
      [ENTITY_TYPE_CATALOG],
      {
        indices: [READ_INDEX_INTERNAL_OBJECTS],
        filters: {
          filters: [
            {
              key: ['catalog_id'],
              values: ['catalog-1'],
              operator: FilterOperator.NotEq,
            },
            {
              key: ['catalog_id'],
              values: ['catalog-2'],
              operator: FilterOperator.NotEq,
            },
          ],
          filterGroups: [],
          mode: FilterMode.And,
        },
      },
    );
  });

  it('should upsert a new catalog on the write alias when no existing catalog is provided', async () => {
    const catalogUpsert = {
      internal_id: 'catalog--1',
      standard_id: 'catalog--standard',
      catalog_id: 'catalog-1',
    } as CatalogUpsert;

    await upsertCatalog(context, user, catalogUpsert);

    expect(elIndex).toHaveBeenCalledWith(INDEX_INTERNAL_OBJECTS, {
      ...catalogUpsert,
      entity_type: ENTITY_TYPE_CATALOG,
    });
  });

  it('should upsert an existing catalog in its existing physical index', async () => {
    const catalogPhysicalIndex = 'opencti_internal_objects-000042';
    const currentCatalog = {
      id: 'catalog--1',
      internal_id: 'catalog--1',
      _index: catalogPhysicalIndex,
    } as BasicStoreEntityCatalog;
    const catalogUpsert = {
      internal_id: 'catalog--1',
      standard_id: 'catalog--standard',
      catalog_id: 'catalog-1',
    } as CatalogUpsert;

    await upsertCatalog(context, user, catalogUpsert, currentCatalog);

    expect(elIndex).toHaveBeenCalledWith(catalogPhysicalIndex, {
      ...catalogUpsert,
      entity_type: ENTITY_TYPE_CATALOG,
    });
  });

  it('should update catalog contracts in their existing physical index', async () => {
    const update = {
      internal_id: contractId,
      standard_id: 'catalog-contract--standard',
      title: 'Updated contract',
    } as CatalogContractUpdate;

    await updateCatalogContracts(context, user, [update]);

    expect(internalFindByIdsMapped).toHaveBeenCalledWith(
      context,
      user,
      [contractId],
      {
        type: ENTITY_TYPE_CATALOG_CONTRACT,
        indices: [READ_INDEX_INTERNAL_OBJECTS],
        baseData: true,
        mapWithAllIds: true,
      },
    );
    expect(elIndexElements).toHaveBeenCalledWith(
      context,
      user,
      ENTITY_TYPE_CATALOG_CONTRACT,
      [{
        ...update,
        _index: physicalIndex,
        entity_type: ENTITY_TYPE_CATALOG_CONTRACT,
      }],
    );
  });

  it('should delete catalog contracts from their existing physical index', async () => {
    await deleteCatalogContracts(context, user, [{ idToDelete: contractId }]);

    expect(elDeleteInstances).toHaveBeenCalledWith(context, [existingContract]);
  });

  it('should reject writes when a catalog contract cannot be located', async () => {
    vi.mocked(internalFindByIdsMapped).mockResolvedValue({});

    await expect(deleteCatalogContracts(
      context,
      user,
      [{ idToDelete: contractId }],
    )).rejects.toThrow('Catalog contracts not found');
    expect(elDeleteInstances).not.toHaveBeenCalled();
  });
});
