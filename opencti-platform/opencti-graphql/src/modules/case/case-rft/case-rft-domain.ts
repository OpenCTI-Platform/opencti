import type { AuthContext, AuthUser } from '../../../types/user';
import { createEntity } from '../../../database/middleware';
import type { EntityOptions } from '../../../database/middleware-loader';
import { internalLoadById, listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import { BUS_TOPICS } from '../../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../../schema/general';
import { notify } from '../../../database/redis';
import { now } from '../../../utils/format';
import { userAddIndividual } from '../../../domain/user';
import { isEmptyField } from '../../../database/utils';
import type { BasicStoreEntityCaseRft } from './case-rft-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from './case-rft-types';
import type { DomainFindById } from '../../../domain/domainTypes';
import type { CaseRftAddInput } from '../../../generated/graphql';
import { isStixId } from '../../../schema/schemaUtils';
import { RELATION_OBJECT } from '../../../schema/stixRefRelationship';

export const findById: DomainFindById<BasicStoreEntityCaseRft> = (context: AuthContext, user: AuthUser, caseRftId: string) => {
  return storeLoadById(context, user, caseRftId, ENTITY_TYPE_CONTAINER_CASE_RFT);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCaseRft>) => {
  return listEntitiesPaginated<BasicStoreEntityCaseRft>(context, user, [ENTITY_TYPE_CONTAINER_CASE_RFT], opts);
};

export const addCaseRft = async (context: AuthContext, user: AuthUser, caseRftAdd: CaseRftAddInput) => {
  let caseToCreate = caseRftAdd.created ? caseRftAdd : { ...caseRftAdd, created: now() };
  if (isEmptyField(caseRftAdd.createdBy)) {
    let individualId = user.individual_id;
    if (individualId === undefined) {
      const individual = await userAddIndividual(context, user);
      individualId = individual.id;
    }
    caseToCreate = { ...caseToCreate, createdBy: individualId };
  }
  const created = await createEntity(context, user, caseToCreate, ENTITY_TYPE_CONTAINER_CASE_RFT);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const caseRftContainsStixObjectOrStixRelationship = async (context: AuthContext, user: AuthUser, caseRftId: string, thingId: string) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).internal_id : thingId;
  const args = {
    filters: [
      { key: 'internal_id', values: [caseRftId] },
      { key: buildRefRelationKey(RELATION_OBJECT), values: [resolvedThingId] },
    ],
  };
  const caseRftFound = await findAll(context, user, args);
  return caseRftFound.edges.length > 0;
};
