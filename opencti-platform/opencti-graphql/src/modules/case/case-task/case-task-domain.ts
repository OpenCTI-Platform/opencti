import { BUS_TOPICS } from '../../../config/conf';
import { createEntity, deleteElementById, updateAttribute } from '../../../database/middleware';
import { EntityOptions, internalLoadById, listEntitiesPaginated, storeLoadById } from '../../../database/middleware-loader';
import { notify } from '../../../database/redis';
import type { DomainFindById } from '../../../domain/domainTypes';
import { CaseTaskAddInput, CaseTasksFilter, EditInput, StixRefRelationshipAddInput, } from '../../../generated/graphql';
import { ABSTRACT_STIX_DOMAIN_OBJECT, buildRefRelationKey } from '../../../schema/general';
import { isStixId } from '../../../schema/schemaUtils';
import { RELATION_OBJECT } from '../../../schema/stixRefRelationship';
import type { AuthContext, AuthUser } from '../../../types/user';
import { BasicStoreEntityCaseTask, ENTITY_TYPE_CONTAINER_CASE_TASK } from './case-task-types';
import { publishUserAction } from '../../../listener/UserActionListener';
import { stixObjectOrRelationshipAddRefRelation, stixObjectOrRelationshipDeleteRefRelation } from '../../../domain/stixObjectOrStixRelationship';
import { extractEntityRepresentative } from '../../../database/utils';
import { ENTITY_TYPE_CASE_TEMPLATE } from '../case-template/case-template-types';

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
  const newInput = { ...input, useAsTemplate: !!input.useAsTemplate };
  const created = await createEntity(context, user, newInput, ENTITY_TYPE_CONTAINER_CASE_TASK);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates Task \`${input.name}\``,
    context_data: { entity_type: ENTITY_TYPE_CONTAINER_CASE_TASK, input }
  });
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const caseTaskDelete = async (context: AuthContext, user: AuthUser, id: string) => {
  const element = await deleteElementById(context, user, id, ENTITY_TYPE_CONTAINER_CASE_TASK);
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, element, user);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes Task \`${element.name}\``,
    context_data: { entity_type: ENTITY_TYPE_CONTAINER_CASE_TASK, input: element }
  });
  return id;
};

export const caseTaskEdit = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  const newInput = input.filter(({ key }) => key !== CaseTasksFilter.UseAsTemplate);
  const { element: updatedElem } = await updateAttribute(context, user, id, ENTITY_TYPE_CONTAINER_CASE_TASK, newInput);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for Task \`${updatedElem.name}\``,
    context_data: { entity_type: ENTITY_TYPE_CONTAINER_CASE_TASK, input }
  });
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

export const caseTaskAddRelation = async (context: AuthContext, user: AuthUser, caseTaskId: string, input: StixRefRelationshipAddInput) => {
  const relation = await stixObjectOrRelationshipAddRefRelation(context, user, caseTaskId, input, ABSTRACT_STIX_DOMAIN_OBJECT);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `adds Task \`${extractEntityRepresentative(relation.from)}\` for case template \`${relation.to.name}\``,
    context_data: { entity_type: ENTITY_TYPE_CASE_TEMPLATE, input }
  });
  return relation;
};

export const caseTaskDeleteRelation = async (context: AuthContext, user: AuthUser, caseTaskId: string, toId: string, relationshipType: string) => {
  const relation = await stixObjectOrRelationshipDeleteRefRelation(context, user, caseTaskId, toId, relationshipType, ABSTRACT_STIX_DOMAIN_OBJECT);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `removes Task \`${extractEntityRepresentative(relation.from)}\` for case template \`${relation.to.name}\``,
    context_data: { entity_type: ENTITY_TYPE_CASE_TEMPLATE, input: { caseTaskId, toId, relationshipType } }
  });
  return relation;
};
