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

import ejs from 'ejs';
import type { AuthContext, AuthUser } from '../../types/user';
import { internalLoadById, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { type DisseminationListAddInput, type DisseminationListSendInput, type EditInput, type QueryDisseminationListsArgs } from '../../generated/graphql';
import { type BasicStoreEntityDisseminationList, ENTITY_TYPE_DISSEMINATION_LIST, type StoreEntityDisseminationList } from './disseminationList-types';
import { completeContextDataForEntity, publishUserAction, type UserDisseminateActionContextData } from '../../listener/UserActionListener';
import conf, { BUS_TOPICS, logApp } from '../../config/conf';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { updateAttribute } from '../../database/middleware';
import { notify } from '../../database/redis';
import { downloadFile, getFileContent, loadFile } from '../../database/file-storage';
import { getEntityFromCache } from '../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { OCTI_EMAIL_TEMPLATE } from '../../utils/emailTemplates/octiEmailTemplate';
import { sendMail } from '../../database/smtp';
import type { BasicStoreSettings } from '../../types/settings';
import { emailChecker } from '../../utils/syntax';
import type { BasicStoreCommon } from '../../types/store';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { addDisseminationCount } from '../../manager/telemetryManager';

const MAX_DISSEMINATION_LIST_SIZE = conf.get('app:dissemination_list:max_list_size') || 500;

export const findById = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  return storeLoadById<BasicStoreEntityDisseminationList>(context, user, id, ENTITY_TYPE_DISSEMINATION_LIST);
};

export const findAll = async (context: AuthContext, user: AuthUser, args: QueryDisseminationListsArgs) => {
  await checkEnterpriseEdition(context);
  return listEntitiesPaginated<BasicStoreEntityDisseminationList>(context, user, [ENTITY_TYPE_DISSEMINATION_LIST], args);
};

interface SendMailArgs {
  from: string;
  to: string;
  bcc?: string[];
  subject: string;
  html: string;
  attachments?: any[];
}

/**
 * Actual sending of email, used by the background task.
 * @param context
 * @param user
 * @param object
 * @param body
 * @param emails
 * @param attachFileIds
 * @param htmlToBodyFileId
 */
export const sendDisseminationEmail = async (
  context: AuthContext,
  user: AuthUser,
  object: string,
  body: string,
  emails: string[],
  attachFileIds: string[],
  htmlToBodyFileId: string | null | undefined,
) => {
  const toEmail = conf.get('app:dissemination_list:to_email');
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  const sentFiles = [];
  const attachmentListForSendMail = [];
  let generatedEmailBody = '';
  const allowedTypesInAttachment = ['application/pdf', 'text/html'];
  const allowedTypesInBody = ['text/html'];

  for (let i = 0; i < attachFileIds.length; i += 1) {
    const attachFileId = attachFileIds[i];
    const file = await loadFile(context, user, attachFileId);
    const canBeDisseminated = file && allowedTypesInAttachment.includes(file.metaData.mimetype);
    if (!canBeDisseminated) {
      throw UnsupportedError('File cant be disseminate', { id: attachFileId });
    }
    sentFiles.push(file);
    const stream = await downloadFile(file.id);
    attachmentListForSendMail.push({ filename: file.name, content: stream });
  }

  if (htmlToBodyFileId) {
    const bodyFile = await loadFile(context, user, htmlToBodyFileId);
    const canBeInBody = bodyFile && allowedTypesInBody.includes(bodyFile.metaData.mimetype);
    if (!canBeInBody) {
      throw UnsupportedError(`File type in the body must be ${allowedTypesInBody}`, { id: htmlToBodyFileId });
    }
    const fileContent = await getFileContent(bodyFile.id);
    generatedEmailBody = ejs.render(OCTI_EMAIL_TEMPLATE, { settings, body: fileContent });
    sentFiles.push(bodyFile);
  } else {
    const emailBodyFormatted = body.replaceAll('\n', '<br/>');
    generatedEmailBody = ejs.render(OCTI_EMAIL_TEMPLATE, { settings, body: emailBodyFormatted });
  }

  const sendMailArgs: SendMailArgs = {
    from: settings.platform_email,
    to: toEmail,
    bcc: [...emails, user.user_email],
    subject: object,
    html: generatedEmailBody,
    attachments: attachmentListForSendMail,
  };
  await sendMail(sendMailArgs);
  addDisseminationCount();
  return sentFiles;
};

export const sendToDisseminationList = async (context: AuthContext, user: AuthUser, id: string, input: DisseminationListSendInput) => {
  const { entity_id, email_body, email_object, email_attachment_ids, html_to_body_file_id } = input;
  logApp.info('Sending email to dissemination list', { id, entity_id, email_object, email_attachment_ids, html_to_body_file_id });

  const disseminationList = await findById(context, user, id);
  const data: BasicStoreCommon = await internalLoadById(context, user, entity_id);

  // precheck
  await checkEnterpriseEdition(context);
  if (!disseminationList || disseminationList.entity_type !== ENTITY_TYPE_DISSEMINATION_LIST) {
    throw FunctionalError(`id is not of type ${ENTITY_TYPE_DISSEMINATION_LIST}`, { id });
  }
  // context entity is mandatory
  if (!data) {
    throw UnsupportedError('Cant find base element of dissemination', { entity_id });
  }

  const { emails } = disseminationList;
  // sending mail
  const sentFiles = await sendDisseminationEmail(context, user, email_object, email_body, emails, email_attachment_ids, html_to_body_file_id);
  // activity logs
  const enrichInput = { ...input, files: sentFiles, dissemination: disseminationList.name };
  const baseData = {
    id: entity_id,
    entity_name: extractEntityRepresentativeName(data),
    entity_type: data.entity_type,
    input: enrichInput,
  };
  const contextData: UserDisseminateActionContextData = completeContextDataForEntity(baseData, data);
  await publishUserAction({
    event_access: 'administration',
    user,
    event_type: 'file',
    event_scope: 'disseminate',
    context_data: contextData
  });
  return true;
};

const validationEmails = (emails: string[]) => {
  // check the limit of emails
  if (emails.length > MAX_DISSEMINATION_LIST_SIZE) {
    throw UnsupportedError(`You cannot have more than ${MAX_DISSEMINATION_LIST_SIZE} e-mail addresses`);
  }
  // check email validity
  if (emails.some((email) => !emailChecker.test(email))) {
    throw UnsupportedError('Emails are not correctly formatted');
  }
};

export const addDisseminationList = async (context: AuthContext, user: AuthUser, input: DisseminationListAddInput) => {
  await checkEnterpriseEdition(context);
  validationEmails(input.emails);
  const disseminationListToCreate = {
    name: input.name,
    emails: input.emails,
    description: input.description,
  };
  return createInternalObject<StoreEntityDisseminationList>(context, user, disseminationListToCreate, ENTITY_TYPE_DISSEMINATION_LIST);
};

export const fieldPatchDisseminationList = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  await checkEnterpriseEdition(context);
  // Get the list
  const disseminationList = await findById(context, user, id);
  if (!disseminationList) {
    throw FunctionalError(`Dissemination list ${id} cannot be found`);
  }
  // Validation emails
  const emailsInput = input.find((editInput) => editInput.key === 'emails');
  if (emailsInput) validationEmails(emailsInput.value);
  // Update the list
  const { element } = await updateAttribute(context, user, id, ENTITY_TYPE_DISSEMINATION_LIST, input);
  // Publish Activity
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for dissemination list \`${element.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_DISSEMINATION_LIST, input }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_DISSEMINATION_LIST].EDIT_TOPIC, element, user);
};

export const deleteDisseminationList = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  return deleteInternalObject(context, user, id, ENTITY_TYPE_DISSEMINATION_LIST);
};
