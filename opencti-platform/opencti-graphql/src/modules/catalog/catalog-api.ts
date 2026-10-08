import { APP_MODULE, withModuleApi } from '../../config/error-origin';
import {
  computeConnectorTargetContract as computeConnectorTargetContractInternal,
  encryptValue as encryptValueInternal,
  mapContractEntityFieldsToEmbeddedConnectorManagerContract as mapContractEntityFieldsToEmbeddedConnectorManagerContractInternal,
  mapContractEntityFieldsToGraphqlCatalogContract as mapContractEntityFieldsToGraphqlCatalogContractInternal,
} from './catalog-domain';
import {
  findCatalogContractsByImageName as findCatalogContractsByImageNameInternal,
  findCatalogContractsBySlugs as findCatalogContractsBySlugsInternal,
  findLatestCompatibleCatalogContractByImageName as findLatestCompatibleCatalogContractByImageNameInternal,
  findLatestCompatibleCatalogContractBySlug as findLatestCompatibleCatalogContractBySlugInternal,
} from './catalog-repository';
import {
  buildConnectorUpdateStatus as buildConnectorUpdateStatusInternal,
  compareContractVersions as compareContractVersionsInternal,
  groupContractVersionsBySlug as groupContractVersionsBySlugInternal,
} from './catalog-version-utils';

// Public API of the catalog module: the only entry point for the code outside it.
// Errors leaving through it are tagged `catalog`, so they are attributed to the catalog
// even when another module's resolver or manager is running (RFC 0006).
export const {
  buildConnectorUpdateStatus,
  compareContractVersions,
  computeConnectorTargetContract,
  encryptValue,
  findCatalogContractsByImageName,
  findCatalogContractsBySlugs,
  findLatestCompatibleCatalogContractByImageName,
  findLatestCompatibleCatalogContractBySlug,
  mapContractEntityFieldsToEmbeddedConnectorManagerContract,
  mapContractEntityFieldsToGraphqlCatalogContract,
  groupContractVersionsBySlug,
} = withModuleApi(APP_MODULE.CATALOG, {
  buildConnectorUpdateStatus: buildConnectorUpdateStatusInternal,
  compareContractVersions: compareContractVersionsInternal,
  computeConnectorTargetContract: computeConnectorTargetContractInternal,
  encryptValue: encryptValueInternal,
  findCatalogContractsByImageName: findCatalogContractsByImageNameInternal,
  findCatalogContractsBySlugs: findCatalogContractsBySlugsInternal,
  findLatestCompatibleCatalogContractByImageName: findLatestCompatibleCatalogContractByImageNameInternal,
  findLatestCompatibleCatalogContractBySlug: findLatestCompatibleCatalogContractBySlugInternal,
  mapContractEntityFieldsToEmbeddedConnectorManagerContract: mapContractEntityFieldsToEmbeddedConnectorManagerContractInternal,
  mapContractEntityFieldsToGraphqlCatalogContract: mapContractEntityFieldsToGraphqlCatalogContractInternal,
  groupContractVersionsBySlug: groupContractVersionsBySlugInternal,
});
