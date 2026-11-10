/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { FilterMode, type EditInput, type EmailTemplateAddInput, type QueryEmailTemplatesArgs } from '../../generated/graphql';
import { type BasicStoreEntityEmailTemplate, ENTITY_TYPE_EMAIL_TEMPLATE, type StoreEntityEmailTemplate } from './emailTemplate-types';
import { sendEmailToUser } from '../user/user-domain';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { FunctionalError } from '../../config/errors';
import { updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { addEmailTemplateCreatedCount } from '../../manager/telemetryManager';

export const findById = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  return storeLoadById<BasicStoreEntityEmailTemplate>(context, user, id, ENTITY_TYPE_EMAIL_TEMPLATE);
};

export const findEmailTemplatePaginated = async (context: AuthContext, user: AuthUser, args: QueryEmailTemplatesArgs) => {
  await checkEnterpriseEdition(context);
  return pageEntitiesConnection<BasicStoreEntityEmailTemplate>(context, user, [ENTITY_TYPE_EMAIL_TEMPLATE], args);
};

export const findAllEmailTemplates = async (context: AuthContext, user: AuthUser, args: Record<string, unknown> = {}) => {
  await checkEnterpriseEdition(context);
  return fullEntitiesList<BasicStoreEntityEmailTemplate>(context, user, [ENTITY_TYPE_EMAIL_TEMPLATE], args);
};

// The name is not unique on the platform: every template that has exactly this name.
// The engine matches a name without its case, but two names that differ by their case are two templates.
export const findEmailTemplatesByName = async (context: AuthContext, user: AuthUser, name: string) => {
  const templates = await findAllEmailTemplates(context, user, {
    filters: { mode: FilterMode.And, filters: [{ key: ['name'], values: [name] }], filterGroups: [] },
  });
  return templates.filter((template) => template.name === name);
};

export const sendTestEmail = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  return sendEmailToUser(context, user, { target_user_id: user.id, email_template_id: id });
};

export const addEmailTemplate = async (context: AuthContext, user: AuthUser, input: EmailTemplateAddInput, useTelemetry: boolean = true) => {
  const emailTemplateToCreate = {
    name: input.name,
    description: input.description,
    email_object: input.email_object,
    sender_email: input.sender_email,
    template_body: input.template_body,
  };
  if (useTelemetry) {
    await addEmailTemplateCreatedCount();
  }
  return createInternalObject<StoreEntityEmailTemplate>(context, user, emailTemplateToCreate, ENTITY_TYPE_EMAIL_TEMPLATE);
};

export const fieldPatchEmailTemplate = async (context: AuthContext, user: AuthUser, emailTemplateId: string, input: EditInput[]) => {
  const emailTemplate = await findById(context, user, emailTemplateId);
  if (!emailTemplate) {
    throw FunctionalError(`Email template ${emailTemplateId} cannot be found`);
  }
  const { element } = await updateAttribute<StoreEntityEmailTemplate>(context, user, emailTemplateId, ENTITY_TYPE_EMAIL_TEMPLATE, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for email template \`${element.name}\``,
    context_data: { id: emailTemplateId, entity_type: ENTITY_TYPE_EMAIL_TEMPLATE, input },
  });

  return notify(BUS_TOPICS[ENTITY_TYPE_EMAIL_TEMPLATE].EDIT_TOPIC, element, user);
};

export const deleteEmailTemplate = async (context: AuthContext, user: AuthUser, emailTemplateId: string) => {
  await checkEnterpriseEdition(context);
  return deleteInternalObject(context, user, emailTemplateId, ENTITY_TYPE_EMAIL_TEMPLATE);
};
