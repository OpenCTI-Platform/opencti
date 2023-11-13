import { BUS_TOPICS } from '../../config/conf';
import {
  createEntity,
} from '../../database/middleware';
import {
  listEntitiesPaginated,
  storeLoadById,
} from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import type { DomainFindAll, DomainFindById } from '../../domain/domainTypes';
import type {
  FinancialAccountAddInput,
  QueryFinancialAccountsArgs,
} from '../../generated/graphql';
import {
  ABSTRACT_STIX_DOMAIN_OBJECT,
} from '../../schema/general';
import type { AuthContext, AuthUser } from '../../types/user';
import {
  type BasicStoreEntityFinancialAccount,
  ENTITY_TYPE_FINANCIAL_ACCOUNT,
} from './financialData-types';

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
