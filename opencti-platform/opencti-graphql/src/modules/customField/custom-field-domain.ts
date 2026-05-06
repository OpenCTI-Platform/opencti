import { type EntityOptions, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityCustomField, ENTITY_TYPE_CUSTOM_FIELD, type StoreEntityCustomField } from './custom-field-types';
import type { EditInput } from '../../generated/graphql';
import type { DomainFindById } from '../../domain/domainTypes';
import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { publishUserAction } from '../../listener/UserActionListener';

// Local type until GraphQL types are regenerated
interface CustomFieldAddInput {
  name: string;
  label: string;
  field_type: string;
  entity_types?: string[] | null;
  mandatory: boolean;
  description?: string | null;
  created?: Date | null;
  // Common optional
  default_value?: string | null;
  // Integer-specific
  min_value?: number | null;
  max_value?: number | null;
}

export const findById: DomainFindById<BasicStoreEntityCustomField> = (context: AuthContext, user: AuthUser, customFieldId: string) => {
  return storeLoadById(context, user, customFieldId, ENTITY_TYPE_CUSTOM_FIELD);
};

export const findCustomFieldsPaginated = (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCustomField>) => {
  return pageEntitiesConnection<BasicStoreEntityCustomField>(context, user, [ENTITY_TYPE_CUSTOM_FIELD], opts);
};

export const customFieldAdd = async (context: AuthContext, user: AuthUser, input: CustomFieldAddInput) => {
  const created = await createEntity(context, user, input, ENTITY_TYPE_CUSTOM_FIELD);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `creates custom field \`${input.name}\``,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_CUSTOM_FIELD, input },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC, created, user);
};

export const customFieldDelete = async (context: AuthContext, user: AuthUser, customFieldId: string) => {
  const element = await deleteElementById<StoreEntityCustomField>(context, user, customFieldId, ENTITY_TYPE_CUSTOM_FIELD);
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, element, user);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes custom field \`${element.name}\``,
    context_data: { id: customFieldId, entity_type: ENTITY_TYPE_CUSTOM_FIELD, input: element },
  });
  return customFieldId;
};

export const customFieldEdit = async (context: AuthContext, user: AuthUser, customFieldId: string, input: EditInput[]) => {
  const { element: updatedElem } = await updateAttribute<StoreEntityCustomField>(context, user, customFieldId, ENTITY_TYPE_CUSTOM_FIELD, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for custom field \`${updatedElem.name}\``,
    context_data: { id: customFieldId, entity_type: ENTITY_TYPE_CUSTOM_FIELD, input },
  });
  return notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElem, user);
};

