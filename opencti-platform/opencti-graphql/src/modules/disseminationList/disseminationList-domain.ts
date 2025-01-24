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
import type { DisseminationListAddInput, DisseminationListSendInput, EditInput, QueryDisseminationListsArgs } from '../../generated/graphql';
import {
  type BasicStoreEntityDisseminationList,
  type BasicStoreEntityDisseminationListName,
  ENTITY_TYPE_DISSEMINATION_LIST,
  type StoreEntityDisseminationList
} from './disseminationList-types';
import { sendMail } from '../../database/smtp';
import { getEntityFromCache } from '../../database/cache';
import type { BasicStoreSettings } from '../../types/settings';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { downloadFile, loadFile } from '../../database/file-storage';
import { buildContextDataForFile, publishUserAction } from '../../listener/UserActionListener';
import { EMAIL_TEMPLATE } from '../../utils/emailTemplates/emailTemplate';
import conf, { BUS_TOPICS, isFeatureEnabled } from '../../config/conf';
import type { BasicStoreObject, StoreEntityConnection } from '../../types/store';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { generateInternalId } from '../../schema/identifier';
import { createInternalObject, deleteInternalObject } from '../../domain/internalObject';
import { updateAttribute } from '../../database/middleware';
import { notify } from '../../database/redis';

const isDisseminationListEnabled = isFeatureEnabled('DISSEMINATIONLIST');

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityDisseminationList>(context, user, id, ENTITY_TYPE_DISSEMINATION_LIST);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QueryDisseminationListsArgs) => {
  return listEntitiesPaginated<BasicStoreEntityDisseminationList>(context, user, [ENTITY_TYPE_DISSEMINATION_LIST], args);
};

export const findAllNames = async (context: AuthContext, user: AuthUser, args: QueryDisseminationListsArgs) => {
  const allLists: StoreEntityConnection<BasicStoreEntityDisseminationList> = await listEntitiesPaginated<BasicStoreEntityDisseminationList>(
    context,
    user,
    [ENTITY_TYPE_DISSEMINATION_LIST],
    args
  );
  const newLists: StoreEntityConnection<BasicStoreEntityDisseminationListName> = { edges: [], pageInfo: allLists.pageInfo };
  allLists.edges.map((edge) => {
    const { node, ...edgeRest } = edge;
    const { emails, ...nodeRest } = node;
    newLists.edges.push({ node: nodeRest, ...edgeRest });
  });
  return newLists;
};

interface SendMailArgs {
  from: string;
  to: string;
  bcc?: string[];
  subject: string;
  html: string;
  attachments?: any[];
}

export const sendToDisseminationList = async (context: AuthContext, user: AuthUser, input: DisseminationListSendInput) => {
  await checkEnterpriseEdition(context);
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  const filePath = input.email_attached_file_id;
  const file = await loadFile(context, user, filePath);
  if (file && file.metaData.mimetype === 'application/pdf' && file.metaData.entity_id) {
    const stream = await downloadFile(file.id);
    const emailBodyFormatted = input.email_body.replaceAll('\n', '<br/>');
    const generatedEmail = ejs.render(EMAIL_TEMPLATE, { settings, body: emailBodyFormatted });
    const toEmail = conf.get('app:dissemination_list:to_email');
    const sendMailArgs: SendMailArgs = {
      from: settings.platform_email,
      to: toEmail,
      bcc: [input.email_address, user.user_email],
      subject: input.email_object,
      html: generatedEmail,
      attachments: [
        {
          filename: file.name,
          content: stream,
        }
      ],
    };
    await sendMail(sendMailArgs);
    const instance = await internalLoadById(context, user, file.metaData.entity_id);
    const data = buildContextDataForFile(instance as BasicStoreObject, file.id, file.name, file.metaData.file_markings, input);
    await publishUserAction({
      event_access: 'administration',
      user,
      event_type: 'file',
      event_scope: 'disseminate',
      context_data: data
    });
    return true;
  }
  return false;
};

const storeAndCreateDisseminationList = async (context: AuthContext, user: AuthUser, input: DisseminationListAddInput) => {
  const disseminationListInternalId = generateInternalId();
  const disseminationListToCreate = {
    name: input.name,
    emails: input.emails,
    description: input.description,
    dissemination_list_values_count: input.emails.split('\n').length,
    internal_id: disseminationListInternalId,
  };
  return createInternalObject<StoreEntityDisseminationList>(context, user, disseminationListToCreate, ENTITY_TYPE_DISSEMINATION_LIST);
};

export const addDisseminationList = async (context: AuthContext, user: AuthUser, input: DisseminationListAddInput) => {
  if (!isDisseminationListEnabled) {
    throw UnsupportedError('Feature not yet available');
  }
  return storeAndCreateDisseminationList(context, user, input);
};

export const fieldPatchDisseminationList = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  const disseminationList = await findById(context, user, id);
  if (!disseminationList) {
    throw FunctionalError(`Dissemination list ${id} cannot be found`);
  }
  const finalInput = [...input];
  const emailsInput = finalInput.find((editInput) => editInput.key === 'emails');
  if (emailsInput) {
    await fieldPatchDisseminationList(context, user, id, [{ key: 'dissemination_list_values_count', value: [emailsInput.value[0].split('\n').length] }]);
  }
  const { element } = await updateAttribute(context, user, id, ENTITY_TYPE_DISSEMINATION_LIST, finalInput);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input?.map((i) => i.key).join(', ')}\` for dissemination list \`${element.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_DISSEMINATION_LIST, input }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_DISSEMINATION_LIST].EDIT_TOPIC, element, user);
};

export const deleteDisseminationList = async (context: AuthContext, user: AuthUser, id: string) => {
  if (!isDisseminationListEnabled) {
    throw UnsupportedError('Feature not yet available');
  }
  return deleteInternalObject(context, user, id, ENTITY_TYPE_DISSEMINATION_LIST);
};
