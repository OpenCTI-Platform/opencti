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

import type { AuthContext, AuthUser } from '../../types/user';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { CONFIG_IMPORT_UNCHANGED_REASON, configImportReasonValue, configImportValidationReason, freeConfigImportName } from '../configImport/configImport-utils';
import { addEmailTemplate, fieldPatchEmailTemplate, findEmailTemplatesByName } from './emailTemplate-domain';
import { EMAIL_TEMPLATE_NAME_MAX_LENGTH, type EmailTemplateImportConfiguration, emailTemplateImportSchema } from './emailTemplate-import-schema';

// The names the earlier items of the same import (or dry run) take, written or not: the template of a name is imported once per import.
// An overwrite reserves the name it targets, a copy the name it takes
export interface EmailTemplateImportOptions extends ConfigImportOptions {
  reservedNames?: Set<string>;
}

export type EmailTemplateImportCode = 'invalid' | 'exists' | 'unchanged' | 'ambiguous' | 'duplicate' | 'name_conflict';

export type EmailTemplateImportResult = ConfigImportResult<EmailTemplateImportConfiguration, EmailTemplateImportCode>;

const refused = (
  status: 'failed' | 'skipped',
  code: EmailTemplateImportCode,
  reason: string,
  exists: boolean,
  configuration?: EmailTemplateImportConfiguration,
): EmailTemplateImportResult => {
  return { status, code, reason, exists, configuration };
};

// The fields an import writes on an existing template. A description that is null or absent leaves the one of the template untouched.
const PATCHABLE_FIELDS = ['description', 'email_object', 'sender_email', 'template_body'] as const;

// The one place where an email template is imported: validates, finds the template by its name and writes it. A refusal is a result, not an error.
// A dry run decides the same result and writes nothing.
// The standard id of a template is random, so its name is its identity: add refuses an existing name, overwrite patches the template that has it,
// else creates it. A name that several templates have is refused, the platform cannot tell which one the import means.
// Copy creates the template under a free name (`name (1)`, ...), whether the name is taken or not: it is never refused for it.
// A name that an earlier item of the same import already took is a duplicate (the platform allows several templates with a name, the export of one
// that has them is a bundle that carries it twice): refused, as the later item would overwrite the template of the earlier one.
export const importEmailTemplate = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { mode, dryRun = false, reservedNames }: EmailTemplateImportOptions,
): Promise<EmailTemplateImportResult> => {
  const parsed = emailTemplateImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('failed', 'invalid', configImportValidationReason(parsed.error), false);
  }
  const { data } = parsed;
  if (mode === ConfigImportMode.Copy) {
    const sameName = await findEmailTemplatesByName(context, user, data.name);
    // The name of the configuration is read once: the first candidate of a copy is that name
    const isTaken = async (candidate: string) => {
      if (reservedNames?.has(candidate)) {
        return true;
      }
      return (candidate === data.name ? sameName : await findEmailTemplatesByName(context, user, candidate)).length > 0;
    };
    const name = await freeConfigImportName(data.name, isTaken, { maxLength: EMAIL_TEMPLATE_NAME_MAX_LENGTH });
    if (!name) {
      return refused('failed', 'name_conflict', 'Email template name already exists', sameName.length > 0, data);
    }
    if (dryRun) {
      reservedNames?.add(name);
    } else {
      await addEmailTemplate(context, user, { ...data, name, description: data.description ?? undefined });
    }
    const reason = name === data.name ? undefined : `Added as "${configImportReasonValue(name)}"`;
    return { status: 'created', exists: sameName.length > 0, configuration: data, reason };
  }
  if (reservedNames?.has(data.name)) {
    // exists is false: the clash is with an earlier item of the bundle, not with a template of the platform. The preview shows the choice
    // between overwrite and copy ("When it already exists") only for an item that exists, so this one is refused without a choice, as for exclusion lists
    return refused('failed', 'duplicate', 'Another email template of the import has this name', false, data);
  }
  if (dryRun) {
    reservedNames?.add(data.name);
  }
  const sameName = await findEmailTemplatesByName(context, user, data.name);
  if (sameName.length > 1) {
    return refused('failed', 'ambiguous', 'Several email templates have this name', true, data);
  }
  const [existing] = sameName;
  if (!existing) {
    if (!dryRun) {
      await addEmailTemplate(context, user, { ...data, description: data.description ?? undefined });
    }
    return { status: 'created', exists: false, configuration: data };
  }
  if (mode === ConfigImportMode.Add) {
    return refused('failed', 'exists', 'Email template already exists', true, data);
  }
  const changes = PATCHABLE_FIELDS.filter((field) => {
    const value = data[field];
    return value !== undefined && value !== null && value !== (existing[field] ?? '');
  });
  if (changes.length === 0) {
    return refused('skipped', 'unchanged', CONFIG_IMPORT_UNCHANGED_REASON, true, data);
  }
  if (!dryRun) {
    await fieldPatchEmailTemplate(context, user, existing.id, changes.map((field) => ({ key: field, value: [data[field] as string] })));
  }
  return { status: 'overwritten', exists: true, configuration: data };
};
