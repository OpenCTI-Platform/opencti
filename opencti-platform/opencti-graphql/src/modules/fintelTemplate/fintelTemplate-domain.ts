import type { AuthContext, AuthUser } from '../../types/user';
import type { EditInput, FintelTemplateAddInput } from '../../generated/graphql';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { type BasicStoreEntityFintelTemplate, ENTITY_TYPE_FINTEL_TEMPLATE } from './fintelTemplate-types';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS, isFeatureEnabled } from '../../config/conf';
import { isEnterpriseEdition } from '../../utils/ee';
import { ForbiddenAccess } from '../../config/errors';
import { storeLoadById } from '../../database/middleware-loader';
import { generateFintelTemplateExecutiveSummary } from '../../utils/fintelTemplate/__executiveSummary.template';
import { fintelTemplateIncidentResponse } from '../../utils/fintelTemplate/__incidentCase.template';

// to customize a template we need : EE, FF enabled
// but also to have the SETTINGS_SETCUSTOMIZATION capability !!
// (don't forget to check the capa if it's not done via a @auth in graphql of your function)
export const canCustomizeTemplate = async (context: AuthContext) => {
  const isEE = await isEnterpriseEdition(context);
  const isFileFromTemplateEnabled = true; // isFeatureEnabled('FILE_FROM_TEMPLATE');
  if (!isEE || !isFileFromTemplateEnabled) {
    throw ForbiddenAccess();
  }
};

export const canViewTemplates = async (context: AuthContext) => {
  const isEE = await isEnterpriseEdition(context);
  const isFileFromTemplateEnabled = isFeatureEnabled('FILE_FROM_TEMPLATE');
  return !(!isEE || !isFileFromTemplateEnabled);
};

export const findById = async (context: AuthContext, user: AuthUser, id: string): Promise<BasicStoreEntityFintelTemplate> => {
  await canViewTemplates(context);
  return storeLoadById(context, user, id, ENTITY_TYPE_FINTEL_TEMPLATE);
};

export const addFintelTemplate = async (
  context: AuthContext,
  user: AuthUser,
  input: FintelTemplateAddInput,
) => {
  await canCustomizeTemplate(context);
  const finalInput: FintelTemplateAddInput = {
    ...input,
    content: input.content ?? '',
    fintel_template_widgets: input.fintel_template_widgets ?? [],
  };
  const created = await createEntity(
    context,
    user,
    finalInput,
    ENTITY_TYPE_FINTEL_TEMPLATE,
  );
  return notify(BUS_TOPICS[ENTITY_TYPE_FINTEL_TEMPLATE].ADDED_TOPIC, created, user);
};

export const fintelTemplateEditField = async (
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
    ENTITY_TYPE_FINTEL_TEMPLATE,
    input,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: 'Update template',
    context_data: { id: element.id, entity_type: ENTITY_TYPE_FINTEL_TEMPLATE, input },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_FINTEL_TEMPLATE].EDIT_TOPIC, element, user);
};

export const fintelTemplateDelete = async (context: AuthContext, user: AuthUser, templateId: string) => {
  await canCustomizeTemplate(context);
  const deleted = await deleteElementById(
    context,
    user,
    templateId,
    ENTITY_TYPE_FINTEL_TEMPLATE,
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'extended',
    message: `deletes template \`${deleted.name}\``,
    context_data: {
      id: deleted.id,
      entity_type: ENTITY_TYPE_FINTEL_TEMPLATE,
      input: deleted,
    },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_FINTEL_TEMPLATE].DELETE_TOPIC, deleted, user).then(() => templateId);
};

export const initFintelTemplates = async (context: AuthContext, user: AuthUser) => {
  const builtInTemplatesInputs = [
    generateFintelTemplateExecutiveSummary('Report'),
    generateFintelTemplateExecutiveSummary('Grouping'),
    fintelTemplateIncidentResponse,
    generateFintelTemplateExecutiveSummary('Case-Incident'),
    generateFintelTemplateExecutiveSummary('Case-Rfi'),
    generateFintelTemplateExecutiveSummary('Case-Rft')
  ];
  await Promise.all(builtInTemplatesInputs
    .map((input) => createEntity(context, user, input, ENTITY_TYPE_FINTEL_TEMPLATE)));
};
