import { BUS_TOPICS } from '../../../config/conf';
import { createEntity, deleteElementById, updateAttribute } from '../../../database/middleware';
import { EntityOptions, internalLoadById, listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import { notify } from '../../../database/redis';
import type { DomainFindById } from '../../../domain/domainTypes';
import { CaseTaskAddInput, CaseTasksFilter, EditInput, } from '../../../generated/graphql';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../../schema/general';
import { isStixId } from '../../../schema/schemaUtils';
import { RELATION_OBJECT } from '../../../schema/stixRefRelationship';
import type { AuthContext, AuthUser } from '../../../types/user';
import { BasicStoreEntityCaseTask, ENTITY_TYPE_CONTAINER_CASE_TASK } from './case-task-types';

export const findById: DomainFindById<BasicStoreEntityCaseTask> = (context: AuthContext, user: AuthUser, templateId: string) => {
  return storeLoadById(context, user, templateId, ENTITY_TYPE_CONTAINER_CASE_TASK);
};

export const findAll = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCaseTask>) => {
  const isTemplateDefined = (opts.filters ?? []).some(({ key }) => key.includes(CaseTasksFilter.UseAsTemplate));
  const args = {
    ...opts,
    filters: [
      ...(opts.filters ?? []),
      ...(isTemplateDefined ? [] : [{ key: [CaseTasksFilter.UseAsTemplate], values: [false] }])
    ]
  };
  return listEntitiesPaginated<BasicStoreEntityCaseTask>(context, user, [ENTITY_TYPE_CONTAINER_CASE_TASK], args);
};

export const caseTaskAdd = async (context: AuthContext, user: AuthUser, input: CaseTaskAddInput) => {
  const newInput = {
    ...input,
    useAsTemplate: !!input?.useAsTemplate,
  };
  const created = await createEntity(context, user, newInput, ENTITY_TYPE_CONTAINER_CASE_TASK);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
export const caseTaskDelete = async (context: AuthContext, user: AuthUser, id: string) => {
  const element = await deleteElementById(context, user, id, ENTITY_TYPE_CONTAINER_CASE_TASK);
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, element, user);
  return id;
};
export const caseTaskEdit = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  const newInput = input.filter(({ key }) => key !== CaseTasksFilter.UseAsTemplate);
  const { element: updatedElem } = await updateAttribute(context, user, id, ENTITY_TYPE_CONTAINER_CASE_TASK, newInput);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, updatedElem, user);
};

export const caseTaskContainsStixObjectOrStixRelationship = async (context: AuthContext, user: AuthUser, caseTaskId: string, thingId: string) => {
  const resolvedThingId = isStixId(thingId) ? (await internalLoadById(context, user, thingId)).internal_id : thingId;
  const args = {
    filters: [
      { key: 'internal_id', values: [caseTaskId] },
      { key: buildRefRelationKey(RELATION_OBJECT), values: [resolvedThingId] },
    ],
  };
  const caseTaskFound = await findAll(context, user, args);
  return caseTaskFound.edges.length > 0;
};
