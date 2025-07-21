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

import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import type { QueryDisseminationListsArgs } from '../../generated/graphql';
import { type BasicStoreEntityEmailTemplate, ENTITY_TYPE_EMAIL_TEMPLATE } from './emailTemplate-types';
import { sendEmailToUser } from '../../domain/user';

export const findById = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  return storeLoadById<BasicStoreEntityEmailTemplate>(context, user, id, ENTITY_TYPE_EMAIL_TEMPLATE);
};

export const findAll = async (context: AuthContext, user: AuthUser, args: QueryDisseminationListsArgs) => {
  await checkEnterpriseEdition(context);
  return listEntitiesPaginated<BasicStoreEntityEmailTemplate>(context, user, [ENTITY_TYPE_EMAIL_TEMPLATE], args);
};

export const sendTestEmail = async (context: AuthContext, user: AuthUser, id: string, userId: string) => {
  await checkEnterpriseEdition(context);
  return sendEmailToUser(context, user, { target_user_id: userId, email_template_id: id });
};
