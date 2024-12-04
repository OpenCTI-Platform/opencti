import type { AuthContext, AuthUser } from '../../types/user';
import type { EditInput, TemplateAddInput } from '../../generated/graphql';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { ENTITY_TYPE_TEMPLATE } from './template-types';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS, isFeatureEnabled } from '../../config/conf';
import { isEnterpriseEdition } from '../../utils/ee';
import { ForbiddenAccess } from '../../config/errors';

export const canCustomizeTemplate = async (context: AuthContext) => {
  const isEE = await isEnterpriseEdition(context);
  const isFileFromTemplateEnabled = isFeatureEnabled('FILE_FROM_TEMPLATE');
  if (!isEE || !isFileFromTemplateEnabled) {
    throw ForbiddenAccess();
  }
};

export const addTemplate = async (
  context: AuthContext,
  user: AuthUser,
  input: TemplateAddInput,
) => {
  await canCustomizeTemplate(context);
  const created = await createEntity(
    context,
    user,
    input,
    ENTITY_TYPE_TEMPLATE,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `creates template \`${created.name}\``,
    context_data: {
      id: created.id,
      entity_type: ENTITY_TYPE_TEMPLATE,
      input,
    },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_TEMPLATE].ADDED_TOPIC, created, user);
};

export const templateEditField = async (
  context: AuthContext,
  user: AuthUser,
  templateId: string,
  input: EditInput[],
) => {
  await canCustomizeTemplate(context);
  const { element } = await updateAttribute(
    context,
    user,
    templateId,
    ENTITY_TYPE_TEMPLATE,
    input,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: 'Update template',
    context_data: { id: element.id, entity_type: ENTITY_TYPE_TEMPLATE, input },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_TEMPLATE].EDIT_TOPIC, element, user);
};

export const templateDelete = async (context: AuthContext, user: AuthUser, templateId: string) => {
  await canCustomizeTemplate(context);
  const deleted = await deleteElementById(
    context,
    user,
    templateId,
    ENTITY_TYPE_TEMPLATE,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'extended',
    message: `deletes template \`${deleted.name}\``,
    context_data: {
      id: deleted.id,
      entity_type: ENTITY_TYPE_TEMPLATE,
      input: deleted,
    },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_TEMPLATE].DELETE_TOPIC, deleted, user).then(() => templateId);
};
