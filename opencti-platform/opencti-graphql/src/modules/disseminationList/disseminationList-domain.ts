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
import { BackgroundTaskScope, type DisseminationListAddInput, type DisseminationListSendInput, type EditInput, type QueryDisseminationListsArgs } from '../../generated/graphql';
import { type BasicStoreEntityDisseminationList, ENTITY_TYPE_DISSEMINATION_LIST, type StoreEntityDisseminationList } from './disseminationList-types';
import { buildContextDataForFile, publishUserAction } from '../../listener/UserActionListener';
import conf, { BUS_TOPICS, isFeatureEnabled, logApp } from '../../config/conf';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { updateAttribute } from '../../database/middleware';
import { notify } from '../../database/redis';
import { ACTION_TYPE_DISSEMINATE, createListTask } from '../../domain/backgroundTask-common';
import { downloadFile, loadFile } from '../../database/file-storage';
import { getEntityFromCache } from '../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { EMAIL_TEMPLATE } from '../../utils/emailTemplates/emailTemplate';
import { sendMail } from '../../database/smtp';
import type { BasicStoreSettings } from '../../types/settings';
import type { BasicStoreObject } from '../../types/store';
import { emailChecker } from '../../utils/syntax';

const isDisseminationListEnabled = isFeatureEnabled('DISSEMINATIONLIST');

const MAX_DISSEMINATION_LIST_SIZE = conf.get('app:dissemination_list:max_list_size') || 500;

export const findById = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  if (!isDisseminationListEnabled) {
    throw UnsupportedError('Feature not yet available');
  }
  return storeLoadById<BasicStoreEntityDisseminationList>(context, user, id, ENTITY_TYPE_DISSEMINATION_LIST);
};

export const findAll = async (context: AuthContext, user: AuthUser, args: QueryDisseminationListsArgs) => {
  await checkEnterpriseEdition(context);
  if (!isDisseminationListEnabled) {
    throw UnsupportedError('Feature not yet available');
  }
  return listEntitiesPaginated<BasicStoreEntityDisseminationList>(context, user, [ENTITY_TYPE_DISSEMINATION_LIST], args);
};

export const sendToDisseminationList = async (context: AuthContext, user: AuthUser, input: DisseminationListSendInput) => {
  await checkEnterpriseEdition(context);
  if (!isDisseminationListEnabled) {
    throw UnsupportedError('Feature not yet available');
  }
  const emailBodyFormatted = input.email_body.replaceAll('\n', '<br/>');

  const data = {
    body: emailBodyFormatted,
    object: input.email_object };

  const taskInput = {
    actions: [{
      type: ACTION_TYPE_DISSEMINATE,
      context: {
        values: [input.email_attached_file_id],
        emailData: data
      }
    }],
    ids: [input.dissemination_list_id],
    scope: BackgroundTaskScope.Dissemination
  };
  await createListTask(context, user, taskInput);
  return true;
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
 */
export const sendDisseminationEmail = async (context: AuthContext, user: AuthUser, object: string, body: string, emails: string[], attachFileIds: string[]) => {
  await checkEnterpriseEdition(context);
  if (!isDisseminationListEnabled) {
    throw UnsupportedError('Feature not yet available');
  }
  logApp.info('Calling send disemination', { object, body, emails, attachFileIds });
  const toEmail = conf.get('app:dissemination_list:to_email');
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);

  const attachementListForSendMail = [];
  const attachementFilesForActivity = [];
  for (let i = 0; i < attachFileIds.length; i += 1) {
    const attachFileId = attachFileIds[i];
    const file = await loadFile(context, user, attachFileId);
    if (file && file.metaData.mimetype === 'application/pdf' && file.metaData.entity_id) {
      const stream = await downloadFile(file.id);
      attachementListForSendMail.push({
        filename: file.name,
        content: stream,
      });
      attachementFilesForActivity.push({
        fileId: file.id,
        fileName: file.name,
        fileMarkings: file.metaData.file_markings,
        fileEntityId: file.metaData.entity_id
      });
    }
  }

  const emailBodyFormatted = body.replaceAll('\n', '<br/>');
  const generatedEmailBody = ejs.render(EMAIL_TEMPLATE, { settings, body: emailBodyFormatted });

  const sendMailArgs: SendMailArgs = {
    from: settings.platform_email,
    to: toEmail,
    bcc: [...emails, user.user_email],
    subject: object,
    html: generatedEmailBody,
    attachments: attachementListForSendMail,
  };
  await sendMail(sendMailArgs);
  logApp.info('[DISSEMINATION] email send.');

  for (let i = 0; i < attachementFilesForActivity.length; i += 1) {
    const disseminatedFile = attachementFilesForActivity[i];

    const instance = await internalLoadById(context, user, disseminatedFile.fileEntityId);
    const data = buildContextDataForFile(instance as BasicStoreObject, disseminatedFile.fileId, disseminatedFile.fileName, disseminatedFile.fileMarkings);
    await publishUserAction({
      event_access: 'administration',
      user,
      event_type: 'file',
      event_scope: 'disseminate',
      context_data: data
    });
  }
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
  if (!isDisseminationListEnabled) {
    throw UnsupportedError('Feature not yet available');
  }
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
  if (!isDisseminationListEnabled) {
    throw UnsupportedError('Feature not yet available');
  }
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
  if (!isDisseminationListEnabled) {
    throw UnsupportedError('Feature not yet available');
  }
  return deleteInternalObject(context, user, id, ENTITY_TYPE_DISSEMINATION_LIST);
};
