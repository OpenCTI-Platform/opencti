import { BUS_TOPICS } from '../../config/conf';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { type EntityOptions, internalLoadById, listEntitiesPaginated, listEntitiesThroughRelationsPaginated, storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import type { DomainFindById } from '../../domain/domainTypes';

import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../schema/general';
import { isStixId } from '../../schema/schemaUtils';
import { RELATION_OBJECT, RELATION_OBJECT_PARTICIPANT } from '../../schema/stixRefRelationship';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityTask, ENTITY_TYPE_CONTAINER_TASK } from './task-types';
import { stixObjectOrRelationshipAddRefRelation, stixObjectOrRelationshipDeleteRefRelation } from '../../domain/stixObjectOrStixRelationship';
import type { EditInput, StixRefRelationshipAddInput, TaskAddInput } from '../../generated/graphql';
import { FilterMode } from '../../generated/graphql';
import { now } from '../../utils/format';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { BasicStoreEntityCase } from '../case/case-types';
import type { BasicStoreCommon } from '../../types/store';

export const findById: DomainFindById<BasicStoreEntityTask> = (context: AuthContext, user: AuthUser, templateId: string) => {
  return storeLoadById(context, user, templateId, ENTITY_TYPE_CONTAINER_TASK);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityTask>) => {
  return listEntitiesPaginated<BasicStoreEntityTask>(context, user, [ENTITY_TYPE_CONTAINER_TASK], opts);
};

export const caseTasksPaginated = async <T extends BasicStoreCommon> (context: AuthContext, user: AuthUser, caseId: string, opts: EntityOptions<T>) => {
  return listEntitiesThroughRelationsPaginated<T>(context, user, caseId, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_TASK, true, false, opts);
};

export const taskParticipantsPaginated = async (context: AuthContext, user: AuthUser, caseId: string, opts: EntityOptions<BasicStoreEntityCase>) => {
  return listEntitiesThroughRelationsPaginated(context, user, caseId, RELATION_OBJECT_PARTICIPANT, ENTITY_TYPE_USER, false, false, opts);
};

export const taskAdd = async (context: AuthContext, user: AuthUser, input: TaskAddInput) => {
  const taskToCreate = input.created ? input : { ...input, created: now() };
  const created = await createEntity(context, user, taskToCreate, ENTITY_TYPE_CONTAINER_TASK);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const taskDelete = async (context: AuthContext, user: AuthUser, id: string) => {
  const element = await deleteElementById(context, user, id, ENTITY_TYPE_CONTAINER_TASK);
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, element, user);
  return id;
};

export const taskEdit = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  const { element: updatedElem } = await updateAttribute(context, user, id, ENTITY_TYPE_CONTAINER_TASK, input);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, updatedElem, user);
};

export const taskContainsStixObjectOrStixRelationship = async (context: AuthContext, user: AuthUser, taskId: string, thingId: string) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).internal_id : thingId;
  const args = {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['internal_id'], values: [taskId] },
        { key: [buildRefRelationKey(RELATION_OBJECT)], values: [resolvedThingId] },
      ],
      filterGroups: [],
    },
  };
  const taskFound = await findAll(context, user, args);
  return taskFound.edges.length > 0;
};

export const taskAddRelation = async (context: AuthContext, user: AuthUser, taskId: string, input: StixRefRelationshipAddInput) => {
  return stixObjectOrRelationshipAddRefRelation(context, user, taskId, input, ABSTRACT_STIX_DOMAIN_OBJECT);
};

export const taskDeleteRelation = async (context: AuthContext, user: AuthUser, taskId: string, toId: string, relationshipType: string) => {
  return stixObjectOrRelationshipDeleteRefRelation(context, user, taskId, toId, relationshipType, ABSTRACT_STIX_DOMAIN_OBJECT);
};
