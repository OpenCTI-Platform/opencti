import type { AuthContext, AuthUser } from '../../types/user';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import type { DisseminationListSendInput, QueryDisseminationListsArgs } from '../../generated/graphql';
import { type BasicStoreEntityDisseminationList, ENTITY_TYPE_DISSEMINATION_LIST } from './disseminationList-types';
import { sendMail } from '../../database/smtp';
import { getEntityFromCache } from '../../database/cache';
import type { BasicStoreSettings } from '../../types/settings';
import { SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';

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
}

export const sendToDisseminationList = async (context: AuthContext, user: AuthUser, input: DisseminationListSendInput) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const sendMailArgs: SendMailArgs = { from: settings.platform_email, to: user.user_email, bcc: [input.email_address], subject: input.email_object, html: input.email_body };
  await sendMail(sendMailArgs);
  return true;
};

// export const addDisseminationList = async (context: AuthContext, user: AuthUser, input: DisseminationListAddInput) => {};
// export const fieldPatchDisseminationList = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {};
// export const deleteDisseminationList = async (context: AuthContext, user: AuthUser, id: string) => {};
