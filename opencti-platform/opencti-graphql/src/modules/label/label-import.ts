import { storeLoadById } from '../../database/middleware-loader';
import { addLabel, labelEditField } from '../../domain/label';
import { generateStandardId, normalizeName } from '../../schema/identifier';
import { ENTITY_TYPE_LABEL } from '../../schema/stixMetaObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { configImportValidationReason } from '../configImport/configImport-utils';
import { type LabelImportConfiguration, labelImportSchema } from './label-import-schema';
import type { BasicStoreEntityLabel } from './label-types';

export type LabelImportCode = 'invalid' | 'exists' | 'copy_unsupported' | 'unchanged';

export type LabelImportResult = ConfigImportResult<LabelImportConfiguration, LabelImportCode>;

// The standard id of a label is derived from its value (case and surrounding spaces do not count): the same on every platform
export const getLabelStandardId = (value: string) => generateStandardId(ENTITY_TYPE_LABEL, { value: normalizeName(value) });

const refused = (status: 'failed' | 'skipped', code: LabelImportCode, reason: string, exists: boolean, configuration?: LabelImportConfiguration): LabelImportResult => {
  return { status, code, reason, exists, configuration };
};

// The one place where a label is imported: validates, finds the label by its value and writes it. A refusal is a result, not an error.
// A dry run decides the same result and writes nothing.
// add: the label must not exist yet. overwrite: a label with the same value is given the color of the configuration, else it is created;
// a color that is null or absent leaves the label untouched. A label is its value: it has no copy.
export const importLabel = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { mode, dryRun = false }: ConfigImportOptions,
): Promise<LabelImportResult> => {
  const parsed = labelImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('failed', 'invalid', configImportValidationReason(parsed.error), false);
  }
  const { value, color } = parsed.data;
  const existing = await storeLoadById<BasicStoreEntityLabel>(context, user, getLabelStandardId(value), ENTITY_TYPE_LABEL);
  if (mode === ConfigImportMode.Copy) {
    return refused('failed', 'copy_unsupported', 'A label has no copy', !!existing, parsed.data);
  }
  if (!existing) {
    if (!dryRun) {
      // addLabel gives a label without color the one it makes of its value
      await addLabel(context, user, { value, color });
    }
    return { status: 'created', exists: false, configuration: parsed.data };
  }
  if (mode === ConfigImportMode.Add) {
    return refused('failed', 'exists', 'Label already exists', true, parsed.data);
  }
  if (!color || color.toLowerCase() === existing.color?.toLowerCase()) {
    return refused('skipped', 'unchanged', 'Nothing to import', true, parsed.data);
  }
  if (!dryRun) {
    await labelEditField(context, user, existing.id, [{ key: 'color', value: [color] }]);
  }
  return { status: 'overwritten', exists: true, configuration: parsed.data };
};
