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

import { emailTemplateImportSchema } from './emailTemplate-import-schema';
import type { BasicStoreEntityEmailTemplate } from './emailTemplate-types';

// The fields of an email template in the configuration: the ones the import accepts, so the import takes the export back as is
const EMAIL_TEMPLATE_EXPORT_FIELDS = emailTemplateImportSchema.keyof().options;

// An email template in the import format. A missing description is left out: the import leaves it as it is
export const exportEmailTemplate = (emailTemplate: BasicStoreEntityEmailTemplate) => {
  const presentFields = EMAIL_TEMPLATE_EXPORT_FIELDS.filter((field) => (emailTemplate[field] ?? null) !== null);
  return Object.fromEntries(presentFields.map((field) => [field, emailTemplate[field]]));
};
