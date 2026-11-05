import { storeLoadById } from '../../database/middleware-loader';
import { createStatusTemplate, statusTemplateEditField } from '../../domain/status';
import { generateStandardId } from '../../schema/identifier';
import { ENTITY_TYPE_STATUS_TEMPLATE } from '../../schema/internalObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { configImportValidationReason } from '../configImport/configImport-utils';
import { type StatusTemplateImportConfiguration, statusTemplateImportSchema } from './statusTemplate-import-schema';
import type { BasicStoreEntityStatusTemplate } from './statusTemplate-types';

export type StatusTemplateImportCode = 'invalid' | 'exists' | 'copy_unsupported' | 'unchanged';

export type StatusTemplateImportResult = ConfigImportResult<StatusTemplateImportConfiguration, StatusTemplateImportCode>;

// The standard id of a status template is derived from its name (case and surrounding spaces do not count): the same on every platform
export const getStatusTemplateStandardId = (name: string) => generateStandardId(ENTITY_TYPE_STATUS_TEMPLATE, { name });

const refused = (
  status: 'failed' | 'skipped',
  code: StatusTemplateImportCode,
  reason: string,
  exists: boolean,
  configuration?: StatusTemplateImportConfiguration,
): StatusTemplateImportResult => ({ status, code, reason, exists, configuration });

// The one place where a status template is imported: validates, finds the template by its name and writes it.
// A refusal is a result, not an error. A dry run decides the same result and writes nothing.
// add: the template must not exist yet. overwrite: a template with the same name is given the color of the configuration, else it is
// created. A status template is its name: it has no copy. The workflows are not part of it: a template is never added to one.
export const importStatusTemplate = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { mode, dryRun = false }: ConfigImportOptions,
): Promise<StatusTemplateImportResult> => {
  const parsed = statusTemplateImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('failed', 'invalid', configImportValidationReason(parsed.error), false);
  }
  const { name, color } = parsed.data;
  const existing = await storeLoadById<BasicStoreEntityStatusTemplate>(context, user, getStatusTemplateStandardId(name), ENTITY_TYPE_STATUS_TEMPLATE);
  if (mode === ConfigImportMode.Copy) {
    return refused('failed', 'copy_unsupported', 'A status template has no copy', !!existing, parsed.data);
  }
  if (!existing) {
    if (!dryRun) {
      await createStatusTemplate(context, user, { name, color });
    }
    return { status: 'created', exists: false, configuration: parsed.data };
  }
  if (mode === ConfigImportMode.Add) {
    return refused('failed', 'exists', 'Status template already exists', true, parsed.data);
  }
  if (color.toLowerCase() === existing.color?.toLowerCase()) {
    return refused('skipped', 'unchanged', 'Already up to date', true, parsed.data);
  }
  if (!dryRun) {
    await statusTemplateEditField(context, user, existing.id, [{ key: 'color', value: [color] }]);
  }
  return { status: 'overwritten', exists: true, configuration: parsed.data };
};
