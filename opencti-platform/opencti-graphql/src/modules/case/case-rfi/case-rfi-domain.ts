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
import type { DomainFindById } from '../../../domain/domainTypes';
import { upsertTemplateForCase } from '../case-domain';
import type { BasicStoreEntityCaseRfi } from './case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from './case-rfi-types';
import type { CaseRfiAddInput } from '../../../generated/graphql';
import { isStixId } from '../../../schema/schemaUtils';
import { RELATION_OBJECT } from '../../../schema/stixRefRelationship';
import { FilterMode } from '../../../generated/graphql';

export const findById: DomainFindById<BasicStoreEntityCaseRfi> = (context: AuthContext, user: AuthUser, caseId: string) => {
  return storeLoadById(context, user, caseId, ENTITY_TYPE_CONTAINER_CASE_RFI);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCaseRfi>) => {
  return listEntitiesPaginated<BasicStoreEntityCaseRfi>(context, user, [ENTITY_TYPE_CONTAINER_CASE_RFI], opts);
};

export const addCaseRfi = async (context: AuthContext, user: AuthUser, caseRfiAdd: CaseRfiAddInput) => {
  let caseToCreate = caseRfiAdd.created ? caseRfiAdd : { ...caseRfiAdd, created: now() };
  if (isEmptyField(caseRfiAdd.createdBy)) {
    let individualId = user.individual_id;
    if (individualId === undefined) {
      const individual = await userAddIndividual(context, user);
      individualId = individual.id;
    }
    caseToCreate = { ...caseToCreate, createdBy: individualId };
  }
  const { caseTemplates } = caseToCreate;
  delete caseToCreate.caseTemplates;
  const created = await createEntity(context, user, caseToCreate, ENTITY_TYPE_CONTAINER_CASE_RFI);
  if (caseTemplates) {
    await Promise.all(caseTemplates.map((caseTemplate) => upsertTemplateForCase(context, user, created.id, caseTemplate)));
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const caseRfiContainsStixObjectOrStixRelationship = async (context: AuthContext, user: AuthUser, caseRfiId: string, thingId: string) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).internal_id : thingId;
  const args = {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['internal_id'], values: [caseRfiId] },
        { key: [buildRefRelationKey(RELATION_OBJECT)], values: [resolvedThingId] },
      ],
      filterGroups: [],
    },
  };
  const caseRfiFound = await findAll(context, user, args);
  return caseRfiFound.edges.length > 0;
};
