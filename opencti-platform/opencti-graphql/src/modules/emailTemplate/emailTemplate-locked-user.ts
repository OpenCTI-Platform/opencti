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

// Kept apart from the email template domain, which imports the users, so that the lock email can find its template
// without importing the lockout back

import { LOCKED_USER_EMAIL_TEMPLATE_INPUT } from '../../database/locked-user-email-template-input';
import { fullEntitiesList } from '../../database/middleware-loader';
import type { AuthContext } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { type BasicStoreEntityEmailTemplate, ENTITY_TYPE_EMAIL_TEMPLATE } from './emailTemplate-types';

// The built-in template for the locked users, as the administrators edited it. As findEmailTemplatesByName, without its
// Enterprise Edition check, which would stop the startup: the engine matches a name without its case,
// but a template whose name differs by its case is another template
export const findLockedUserEmailTemplate = async (context: AuthContext) => {
  const filters = addFilter(undefined, 'name', LOCKED_USER_EMAIL_TEMPLATE_INPUT.name);
  const templates = await fullEntitiesList<BasicStoreEntityEmailTemplate>(context, SYSTEM_USER, [ENTITY_TYPE_EMAIL_TEMPLATE], { filters });
  return templates.find((template) => template.name === LOCKED_USER_EMAIL_TEMPLATE_INPUT.name);
};
