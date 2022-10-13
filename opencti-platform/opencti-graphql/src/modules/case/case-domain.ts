import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity } from '../../database/middleware';
import {
  BasicStoreEntityCase,
  ENTITY_TYPE_CONTAINER_CASE,
} from './case-types';
import type { EntityOptions } from '../../database/middleware-loader';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { notify } from '../../database/redis';
import type { CaseAddInput } from '../../generated/graphql';
import { now } from '../../utils/format';
import { addIndividual } from '../../domain/individual';
import { userSessionRefresh } from '../../domain/user';
import { isEmptyField } from '../../database/utils';

export const findById = (context: AuthContext, user: AuthUser, caseId: string): BasicStoreEntityCase => {
  return storeLoadById(context, user, caseId, ENTITY_TYPE_CONTAINER_CASE) as unknown as BasicStoreEntityCase;
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCase>) => {
  return listEntitiesPaginated<BasicStoreEntityCase>(context, user, [ENTITY_TYPE_CONTAINER_CASE], opts);
};

export const addCase = async (context: AuthContext, user: AuthUser, caseAdd: CaseAddInput) => {
  let caseToCreate = caseAdd.created ? caseAdd : { ...caseAdd, created: now() };
  if (isEmptyField(caseAdd.createdBy)) {
    let individualId = user.individual_id;
    if (individualId === undefined) {
      const individual = await addIndividual(context, user, { name: user.name, contact_information: user.user_email });
      individualId = individual.id;
      await userSessionRefresh(user.internal_id);
    }
    caseToCreate = { ...caseToCreate, createdBy: individualId };
  }
  const created = await createEntity(context, user, caseToCreate, ENTITY_TYPE_CONTAINER_CASE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
