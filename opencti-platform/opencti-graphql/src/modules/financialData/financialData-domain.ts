import { BUS_TOPICS } from '../../config/conf';
import {
  createEntity,
} from '../../database/middleware';
import {
  listEntitiesPaginated,
  storeLoadById,
} from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { ES_INDEX_PREFIX } from '../../database/utils';
import type { DomainFindAll, DomainFindById } from '../../domain/domainTypes';
import type {
  FinancialAccountAddInput,
  FinancialAccountUpdateInput,
  FinancialAssetAddInput,
  FinancialAssetUpdateInput,
  QueryFinancialAccountsArgs,
  QueryFinancialAssetsArgs,
} from '../../generated/graphql';
import {
  ABSTRACT_STIX_DOMAIN_OBJECT,
} from '../../schema/general';
import type { AuthContext, AuthUser } from '../../types/user';
import {
  type BasicStoreEntityFinancialAccount,
  type BasicStoreEntityFinancialAsset,
  ENTITY_TYPE_FINANCIAL_ACCOUNT,
  ENTITY_TYPE_FINANCIAL_ASSET,
} from './financialData-types';

const INDEX_STIX_DOMAIN_OBJECTS = `${ES_INDEX_PREFIX}_stix_domain_objects`;

// Accounts
export const findFinancialAccountById: DomainFindById<BasicStoreEntityFinancialAccount> = (
  context: AuthContext,
  user: AuthUser,
  id: string
) => {
  return storeLoadById(context, user, id, ENTITY_TYPE_FINANCIAL_ACCOUNT);
};
export const findAllFinancialAccounts: DomainFindAll<BasicStoreEntityFinancialAccount> = (
  context: AuthContext,
  user: AuthUser,
  opts: QueryFinancialAccountsArgs
) => {
  return listEntitiesPaginated<BasicStoreEntityFinancialAccount>(
    context,
    user,
    [ENTITY_TYPE_FINANCIAL_ACCOUNT],
    opts,
  );
};
export const addFinancialAccount = async (
  context: AuthContext,
  user: AuthUser,
  financialAccount: FinancialAccountAddInput
) => {
  const created = await createEntity(
    context,
    user,
    financialAccount,
    ENTITY_TYPE_FINANCIAL_ACCOUNT
  );
  return notify(
    BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC,
    created,
    user
  );
};
export const updateFinancialAccount = async (
  user: AuthUser,
  financialAccount: FinancialAccountUpdateInput
) => {
  return null;
  // return updateManyFinancialAccounts(
  //   user,
  //   [financialAccount],
  //   true,
  // );
};

// Assets
export const findFinancialAssetById: DomainFindById<BasicStoreEntityFinancialAsset> = (
  context: AuthContext,
  user: AuthUser,
  id: string
) => {
  return storeLoadById(context, user, id, ENTITY_TYPE_FINANCIAL_ASSET);
};
export const findAllFinancialAssets: DomainFindAll<BasicStoreEntityFinancialAsset> = (
  context: AuthContext,
  user: AuthUser,
  opts: QueryFinancialAssetsArgs
) => {
  return listEntitiesPaginated<BasicStoreEntityFinancialAsset>(
    context,
    user,
    [ENTITY_TYPE_FINANCIAL_ASSET],
    opts,
  );
};
export const addFinancialAsset = async (
  context: AuthContext,
  user: AuthUser,
  financialAsset: FinancialAssetAddInput
) => {
  const created = await createEntity(
    context,
    user,
    financialAsset,
    ENTITY_TYPE_FINANCIAL_ASSET
  );
  return notify(
    BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC,
    created,
    user
  );
};
export const updateFinancialAsset = async (
  user: AuthUser,
  financialAsset: FinancialAssetUpdateInput
) => {
  return null;
  // return updateManyFinancialAssets(
  //   user,
  //   [financialAsset],
  //   true,
  // );
};
