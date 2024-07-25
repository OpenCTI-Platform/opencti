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
import { upsertTemplateForCase } from '../case-domain';
import type { BasicStoreEntityCaseIncident } from './case-incident-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from './case-incident-types';
import type { DomainFindById } from '../../../domain/domainTypes';
import type { CaseIncidentAddInput, MemberAccessInput } from '../../../generated/graphql';
import { isStixId } from '../../../schema/schemaUtils';
import { RELATION_OBJECT } from '../../../schema/stixRefRelationship';
import { FilterMode } from '../../../generated/graphql';
import { editAuthorizedMembers } from '../../../utils/authorizedMembers';
import { UnsupportedError } from '../../../config/errors';

export const findById: DomainFindById<BasicStoreEntityCaseIncident> = (context: AuthContext, user: AuthUser, caseIncidentId: string) => {
  return storeLoadById(context, user, caseIncidentId, ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCaseIncident>) => {
  return listEntitiesPaginated<BasicStoreEntityCaseIncident>(context, user, [ENTITY_TYPE_CONTAINER_CASE_INCIDENT], opts);
};

export const addCaseIncident = async (context: AuthContext, user: AuthUser, caseIncidentAdd: CaseIncidentAddInput) => {
  let caseToCreate = caseIncidentAdd.created ? caseIncidentAdd : { ...caseIncidentAdd, created: now() };
  if (isEmptyField(caseIncidentAdd.createdBy)) {
    let individualId = user.individual_id;
    if (individualId === undefined) {
      const individual = await userAddIndividual(context, user);
      individualId = individual.id;
    }
    caseToCreate = { ...caseToCreate, createdBy: individualId };
  }
  const { caseTemplates } = caseToCreate;
  delete caseToCreate.caseTemplates;
  const created = await createEntity(context, user, caseToCreate, ENTITY_TYPE_CONTAINER_CASE_INCIDENT);
  if (caseTemplates) {
    await Promise.all(caseTemplates.map((caseTemplate) => upsertTemplateForCase(context, user, created.id, caseTemplate)));
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const caseIncidentContainsStixObjectOrStixRelationship = async (context: AuthContext, user: AuthUser, caseIncidentId: string, thingId: string) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).internal_id : thingId;
  const args = {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['internal_id'], values: [caseIncidentId] },
        { key: [buildRefRelationKey(RELATION_OBJECT)], values: [resolvedThingId] },
      ],
      filterGroups: [],
    },
  };
  const caseIncidentFound = await findAll(context, user, args);
  return caseIncidentFound.edges.length > 0;
};

export const caseIncidentEditAuthorizedMembers = async (
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
    entityType: ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
    busTopicKey: ABSTRACT_STIX_CORE_OBJECT,
  };
  // @ts-expect-error TODO improve busTopicKey types to avoid this
  return editAuthorizedMembers(context, user, args);
};
