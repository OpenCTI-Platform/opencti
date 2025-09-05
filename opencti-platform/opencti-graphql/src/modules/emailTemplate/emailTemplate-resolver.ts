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

import type { Resolvers } from '../../generated/graphql';
import { findById, findEmailTemplatePaginated, sendTestEmail, addEmailTemplate, deleteEmailTemplate, fieldPatchEmailTemplate } from './emailTemplate-domain';

const emailTemplateResolver: Resolvers = {
  Query: {
    emailTemplate: (_, { id }, context) => findById(context, context.user, id),
    emailTemplates: (_, args, context) => findEmailTemplatePaginated(context, context.user, args),
  },
  EmailTemplate: {},
  Mutation: {
    emailTemplateAdd: (_, { input }, context) => {
      return addEmailTemplate(context, context.user, input);
    },
    emailTemplateDelete: (_, { id }, context) => {
      return deleteEmailTemplate(context, context.user, id);
    },
    emailTemplateFieldPatch: (_, { id, input }, context) => {
      return fieldPatchEmailTemplate(context, context.user, id, input);
    },
    emailTemplateTestSend: (_, { id }, context) => {
      return sendTestEmail(context, context.user, id);
    },
  }
};

export default emailTemplateResolver;
