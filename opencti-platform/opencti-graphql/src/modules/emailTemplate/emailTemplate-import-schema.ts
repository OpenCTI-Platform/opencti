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

import { z } from 'zod';

// At most 512 characters: the name is indexed as a keyword up to there, a longer one could not be found again and would be added at every import
export const EMAIL_TEMPLATE_NAME_MAX_LENGTH = 512;

// The rules of an email template to import, whatever the source (a configuration preset): the ones of the emailTemplateAdd mutation,
// strict, unknown keys are rejected. The values are trimmed, as the engine trims every string it stores: a value compared with the stored one
// must be the one that will be stored. The name is the identity of the template at import.
export const emailTemplateImportSchema = z.strictObject({
  // The standard id of an email template is random: it is not part of the configuration
  name: z.string().trim().min(2, 'Name must have at least 2 characters').max(EMAIL_TEMPLATE_NAME_MAX_LENGTH, `Name must have at most ${EMAIL_TEMPLATE_NAME_MAX_LENGTH} characters`),
  // Absent or null: a new template has none, an existing one keeps its own
  description: z.string().trim().nullable().optional(),
  email_object: z.string().trim().min(2, 'Email object must have at least 2 characters'),
  // The name the sender is shown with: the platform adds the address of its SMTP configuration
  sender_email: z.string().trim(),
  template_body: z.string().trim(),
});

export type EmailTemplateImportConfiguration = z.infer<typeof emailTemplateImportSchema>;
