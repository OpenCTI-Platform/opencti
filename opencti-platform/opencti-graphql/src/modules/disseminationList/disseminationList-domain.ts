/*
Copyright (c) 2021-2024 Filigran SAS

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
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import type { DisseminationListSendInput, QueryDisseminationListsArgs } from '../../generated/graphql';
import { type BasicStoreEntityDisseminationList, ENTITY_TYPE_DISSEMINATION_LIST } from './disseminationList-types';
import { sendMail } from '../../database/smtp';
import { getEntityFromCache } from '../../database/cache';
import type { BasicStoreSettings } from '../../types/settings';
import { SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { downloadFile, loadFile } from '../../database/file-storage';
import { buildContextDataForFile, publishUserAction } from '../../listener/UserActionListener';
import { EMAIL_TEMPLATE } from '../../utils/emailTemplates/emailTemplate';
import conf from '../../config/conf';

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityDisseminationList>(context, user, id, ENTITY_TYPE_DISSEMINATION_LIST);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QueryDisseminationListsArgs) => {
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

export const sendToDisseminationList = async (context: AuthContext, user: AuthUser, input: DisseminationListSendInput) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const filePath = input.email_attached_file_id;
  const file = await loadFile(context, user, filePath);
  if (file && file.metaData.mimetype === 'application/pdf' && settings.valid_enterprise_edition) {
    const stream = await downloadFile(file.id);
    const emailBodyFormatted = input.email_body.replaceAll('\n', '<br/>');
    const generatedEmail = ejs.render(EMAIL_TEMPLATE, { settings, body: emailBodyFormatted });
    const fromEmail = conf.get('smtp:from_email');
    const sendMailArgs: SendMailArgs = {
      from: fromEmail || settings.platform_email,
      to: settings.platform_email,
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
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-expect-error
    const data = buildContextDataForFile(null, file.id, file.name);
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

// export const addDisseminationList = async (context: AuthContext, user: AuthUser, input: DisseminationListAddInput) => {};
// export const fieldPatchDisseminationList = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {};
// export const deleteDisseminationList = async (context: AuthContext, user: AuthUser, id: string) => {};
