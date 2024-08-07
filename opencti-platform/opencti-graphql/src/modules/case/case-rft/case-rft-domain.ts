import type { AuthContext, AuthUser } from '../../../types/user';
import { createEntity } from '../../../database/middleware';
import type { EntityOptions } from '../../../database/middleware-loader';
import { internalLoadById, listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import { BUS_TOPICS, isFeatureEnabled } from '../../../config/conf';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../../schema/general';
import { notify } from '../../../database/redis';
import { now } from '../../../utils/format';
import { userAddIndividual } from '../../../domain/user';
import { isEmptyField } from '../../../database/utils';
import type { DomainFindById } from '../../../domain/domainTypes';
import { isStixId } from '../../../schema/schemaUtils';
import { RELATION_OBJECT } from '../../../schema/stixRefRelationship';
import { upsertTemplateForCase } from '../case-domain';
import type { BasicStoreEntityCaseRft } from './case-rft-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from './case-rft-types';
import type { CaseRftAddInput, MemberAccessInput } from '../../../generated/graphql';
import { FilterMode } from '../../../generated/graphql';
import { UnsupportedError } from '../../../config/errors';
import { editAuthorizedMembers } from '../../../utils/authorizedMembers';

export const findById: DomainFindById<BasicStoreEntityCaseRft> = (context: AuthContext, user: AuthUser, caseId: string) => {
  return storeLoadById(context, user, caseId, ENTITY_TYPE_CONTAINER_CASE_RFT);
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
  const { caseTemplates } = caseToCreate;
  delete caseToCreate.caseTemplates;
  const created = await createEntity(context, user, caseToCreate, ENTITY_TYPE_CONTAINER_CASE_RFT);
  if (caseTemplates) {
    await Promise.all(caseTemplates.map((caseTemplate) => upsertTemplateForCase(context, user, created.id, caseTemplate)));
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const caseRftContainsStixObjectOrStixRelationship = async (context: AuthContext, user: AuthUser, caseRftId: string, thingId: string) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).internal_id : thingId;
  const args = {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['internal_id'], values: [caseRftId] },
        { key: [buildRefRelationKey(RELATION_OBJECT)], values: [resolvedThingId] },
      ],
      filterGroups: [],
    },
  };
  const caseRftFound = await findAll(context, user, args);
  return caseRftFound.edges.length > 0;
};

export const caseRftEditAuthorizedMembers = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  input: MemberAccessInput[] | undefined | null,
) => {
  if (!isFeatureEnabled('CONTAINERS_AUTHORIZED_MEMBERS')) {
    throw UnsupportedError('This feature is disabled');
  }
  const args = {
    entityId,
    input,
    requiredCapabilities: ['KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS'],
    entityType: ENTITY_TYPE_CONTAINER_CASE_RFT,
    busTopicKey: ABSTRACT_STIX_CORE_OBJECT,
  };
  // @ts-expect-error TODO improve busTopicKey types to avoid this
  return editAuthorizedMembers(context, user, args);
};