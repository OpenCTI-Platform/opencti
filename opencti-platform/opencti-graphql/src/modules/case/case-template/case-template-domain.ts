import { type EntityOptions, fullEntitiesList, pageEntitiesConnection, pageRegardingEntitiesConnection, storeLoadById } from '../../../database/middleware-loader';
import { type BasicStoreEntityCaseTemplate, ENTITY_TYPE_CASE_TEMPLATE, TEMPLATE_TASK_RELATION } from './case-template-types';
import { type CaseTemplateAddInput, type EditInput, FilterMode, type StixRefRelationshipAddInput } from '../../../generated/graphql';
import type { DomainFindById } from '../../../domain/domainTypes';
import type { AuthContext, AuthUser } from '../../../types/user';
import { createEntity, deleteElementById, updateAttribute } from '../../../database/middleware';
import { notify } from '../../../database/redis';
import { BUS_TOPICS } from '../../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT, buildRefRelationKey } from '../../../schema/general';
import { publishUserAction } from '../../../listener/UserActionListener';
import { stixObjectOrRelationshipAddRefRelation, stixObjectOrRelationshipDeleteRefRelation } from '../../../domain/stixObjectOrStixRelationship';
import { extractEntityRepresentativeName } from '../../../database/entity-representative';
import { type BasicStoreEntityTaskTemplate, ENTITY_TYPE_TASK_TEMPLATE, type StoreEntityTaskTemplate } from '../../task/task-template/task-template-types';
import type { BasicStoreEntityCase, StoreEntityCase } from '../case-types';
import { normalizeName } from '../../../schema/identifier';

export const findById: DomainFindById<BasicStoreEntityCaseTemplate> = (context: AuthContext, user: AuthUser, templateId: string) => {
  return storeLoadById(context, user, templateId, ENTITY_TYPE_CASE_TEMPLATE);
};
export const findCaseTemplatePaginated = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCaseTemplate>) => {
  return pageEntitiesConnection<BasicStoreEntityCaseTemplate>(context, user, [ENTITY_TYPE_CASE_TEMPLATE], opts);
};

export const findAllCaseTemplates = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCaseTemplate> = {}) => {
  return fullEntitiesList<BasicStoreEntityCaseTemplate>(context, user, [ENTITY_TYPE_CASE_TEMPLATE], opts);
};

// The case templates that have this name, whatever its case. The filter on a name is an exact match on the index (lowercased), so only the
// candidates are read, not every case template: the comparison is made again here, as the importer decides on it.
export const findCaseTemplatesByName = async (context: AuthContext, user: AuthUser, name: string) => {
  const candidates = await findAllCaseTemplates(context, user, {
    filters: { mode: FilterMode.And, filters: [{ key: ['name'], values: [name] }], filterGroups: [] },
  });
  return candidates.filter((template) => normalizeName(template.name) === normalizeName(name));
};

// The task templates of a case template, read as they are to create the tasks of a case (see upsertTemplateForCase)
export const findAllCaseTemplateTasks = (context: AuthContext, user: AuthUser, caseTemplateId: string) => {
  return fullEntitiesList<BasicStoreEntityTaskTemplate>(context, user, [ENTITY_TYPE_TASK_TEMPLATE], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: [buildRefRelationKey(TEMPLATE_TASK_RELATION)], values: [caseTemplateId] }],
      filterGroups: [],
    },
  });
};

export const taskTemplatesPaginated = async (context: AuthContext, user: AuthUser, caseId: string, opts: EntityOptions<BasicStoreEntityCase>) => {
  return pageRegardingEntitiesConnection(context, user, caseId, TEMPLATE_TASK_RELATION, ENTITY_TYPE_TASK_TEMPLATE, false, opts);
};

export const caseTemplateAdd = async (context: AuthContext, user: AuthUser, input: CaseTemplateAddInput) => {
  const created = await createEntity(context, user, input, ENTITY_TYPE_CASE_TEMPLATE);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates case template \`${input.name}\``,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_CASE_TEMPLATE, input },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, created, user);
};
export const caseTemplateDelete = async (context: AuthContext, user: AuthUser, caseTemplateId: string) => {
  const element = await deleteElementById<StoreEntityCase>(context, user, caseTemplateId, ENTITY_TYPE_CASE_TEMPLATE);
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, element, user);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes case template \`${element.name}\``,
    context_data: { id: caseTemplateId, entity_type: ENTITY_TYPE_CASE_TEMPLATE, input: element },
  });
  return caseTemplateId;
};
export const caseTemplateEdit = async (context: AuthContext, user: AuthUser, caseTemplateId: string, input: EditInput[]) => {
  const { element: updatedElem } = await updateAttribute<StoreEntityTaskTemplate>(context, user, caseTemplateId, ENTITY_TYPE_CASE_TEMPLATE, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for case template \`${updatedElem.name}\``,
    context_data: { id: caseTemplateId, entity_type: ENTITY_TYPE_CASE_TEMPLATE, input },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user);
};
export const caseTemplateAddRelation = async (context: AuthContext, user: AuthUser, caseTemplateId: string, input: StixRefRelationshipAddInput) => {
  const relation = await stixObjectOrRelationshipAddRefRelation(context, user, caseTemplateId, input, ABSTRACT_INTERNAL_OBJECT);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `adds Task template \`${extractEntityRepresentativeName(relation.from)}\` for case template \`${relation.to.name}\``,
    context_data: { id: caseTemplateId, entity_type: ENTITY_TYPE_CASE_TEMPLATE, input },
  });
  return relation.to;
};
export const caseTemplateDeleteRelation = async (context: AuthContext, user: AuthUser, caseTemplateId: string, toId: string, relationshipType: string) => {
  const caseTemplate = await stixObjectOrRelationshipDeleteRefRelation(context, user, caseTemplateId, toId, relationshipType, ABSTRACT_INTERNAL_OBJECT);
  const task = await storeLoadById(context, user, toId, ENTITY_TYPE_TASK_TEMPLATE) as BasicStoreEntityTaskTemplate;
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `removes Task template \`${task.name}\` for case template \`${caseTemplate.name}\``,
    context_data: { id: caseTemplateId, entity_type: ENTITY_TYPE_CASE_TEMPLATE, input: { caseTemplateId, toId, relationshipType } },
  });
  return caseTemplate.to;
};
