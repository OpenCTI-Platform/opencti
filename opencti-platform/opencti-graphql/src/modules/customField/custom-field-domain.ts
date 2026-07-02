import { type EntityOptions, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityCustomFieldDefinition, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION, type StoreEntityCustomFieldDefinition } from './custom-field-types';
import type { CustomFieldDefinitionAddInput, EditInput } from '../../generated/graphql';
import { EditOperation, FilterMode, FilterOperator } from '../../generated/graphql';
import type { DomainFindById } from '../../domain/domainTypes';
import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { publishUserAction } from '../../listener/UserActionListener';

// FIXME POC hack
export const CF_SCORE_KEY = 'x_opencti_cf_score';
export const CF_COMMENT_KEY = 'x_opencti_cf_comment';

export const findById: DomainFindById<BasicStoreEntityCustomFieldDefinition> = (context: AuthContext, user: AuthUser, customFieldDefinitionId: string) => {
  return storeLoadById(context, user, customFieldDefinitionId, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION);
};

export const findCustomFieldDefinitionsPaginated = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCustomFieldDefinition>) => {
  return pageEntitiesConnection<BasicStoreEntityCustomFieldDefinition>(context, user, [ENTITY_TYPE_CUSTOM_FIELD_DEFINITION], opts);
};

export const findCustomFieldDefinitionsForEntityType = (context: AuthContext, user: AuthUser, entityType: string) => {
  const filters = {
    mode: FilterMode.And,
    filters: [{ key: ['entity_types'], values: [entityType], operator: FilterOperator.Eq }],
    filterGroups: [],
  };
  return pageEntitiesConnection<BasicStoreEntityCustomFieldDefinition>(context, user, [ENTITY_TYPE_CUSTOM_FIELD_DEFINITION], { filters });
};

export const findCustomFieldDefinitionByName = async (
  context: AuthContext,
  user: AuthUser,
  name: string
): Promise<BasicStoreEntityCustomFieldDefinition | null> => {
  const result = await findCustomFieldDefinitionsPaginated(context, user, {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['name'], values: [name], operator: FilterOperator.Eq }],
      filterGroups: [],
    },
    first: 1,
  });
  return result.edges.length > 0 ? result.edges[0].node : null;
};

export const customFieldDefinitionAdd = async (context: AuthContext, user: AuthUser, input: CustomFieldDefinitionAddInput) => {
  const created = await createEntity(context, user, input, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates custom field definition \`${input.name}\``,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_CUSTOM_FIELD_DEFINITION, input },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, created, user);
};

export const customFieldDefinitionDelete = async (context: AuthContext, user: AuthUser, customFieldDefinitionId: string) => {
  const element = await deleteElementById<StoreEntityCustomFieldDefinition>(context, user, customFieldDefinitionId, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION);
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, element, user);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes custom field definition \`${element.name}\``,
    context_data: { id: customFieldDefinitionId, entity_type: ENTITY_TYPE_CUSTOM_FIELD_DEFINITION, input: element },
  });
  return customFieldDefinitionId;
};

export const customFieldDefinitionEdit = async (context: AuthContext, user: AuthUser, customFieldDefinitionId: string, input: EditInput[]) => {
  const { element: updatedElem } = await updateAttribute<StoreEntityCustomFieldDefinition>(context, user, customFieldDefinitionId, ENTITY_TYPE_CUSTOM_FIELD_DEFINITION, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for custom field definition \`${updatedElem.name}\``,
    context_data: { id: customFieldDefinitionId, entity_type: ENTITY_TYPE_CUSTOM_FIELD_DEFINITION, input },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user);
};

export const customFieldDefinitionAddEntityType = (context: AuthContext, user: AuthUser, customFieldDefinitionId: string, entityType: string) => {
  return customFieldDefinitionEdit(context, user, customFieldDefinitionId, [{ key: 'entity_types', value: [entityType], operation: EditOperation.Add }]);
};

export const customFieldDefinitionRemoveEntityType = (context: AuthContext, user: AuthUser, customFieldDefinitionId: string, entityType: string) => {
  return customFieldDefinitionEdit(context, user, customFieldDefinitionId, [{ key: 'entity_types', value: [entityType], operation: EditOperation.Remove }]);
};
