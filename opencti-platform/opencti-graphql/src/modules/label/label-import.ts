import { storeLoadById } from '../../database/middleware-loader';
import { addLabel, labelEditField } from '../../domain/label';
import { generateStandardId, normalizeName } from '../../schema/identifier';
import { ENTITY_TYPE_LABEL } from '../../schema/stixMetaObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { configImportCopyReason, configImportValidationReason, freeConfigImportName } from '../configImport/configImport-utils';
import { type LabelImportConfiguration, labelImportSchema } from './label-import-schema';
import type { BasicStoreEntityLabel } from './label-types';

export type LabelImportCode = 'invalid' | 'exists' | 'name_conflict' | 'unchanged';

export type LabelImportResult = ConfigImportResult<LabelImportConfiguration, LabelImportCode>;

// The standard id of a label is derived from its value (case and surrounding spaces do not count): the same on every platform
export const getLabelStandardId = (value: string) => generateStandardId(ENTITY_TYPE_LABEL, { value: normalizeName(value) });

const refused = (status: 'failed' | 'skipped', code: LabelImportCode, reason: string, exists: boolean, configuration?: LabelImportConfiguration): LabelImportResult => {
  return { status, code, reason, exists, configuration };
};

// The one place where a label is imported: validates, finds the label by its value and writes it. A refusal is a result, not an error.
// A dry run decides the same result and writes nothing.
// add: the label must not exist yet. overwrite: a label with the same value is given the color of the configuration, else it is created;
// a color that is null or absent leaves the label untouched. copy: a label is its value, so the copy of one that exists is another label,
// under the first free `value (n)`.
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
    const copyValue = await freeConfigImportName(value, async (candidate) => !!(await storeLoadById(context, user, getLabelStandardId(candidate), ENTITY_TYPE_LABEL)));
    if (!copyValue) {
      return refused('failed', 'name_conflict', 'Label already exists', !!existing, parsed.data);
    }
    if (!dryRun) {
      await addLabel(context, user, { value: copyValue, color });
    }
    return { status: 'created', exists: !!existing, configuration: parsed.data, reason: configImportCopyReason(value, copyValue) };
  }
  // What an import does with a label that exists: add refuses it, overwrite gives it the color of the configuration
  const importExisting = async (label: BasicStoreEntityLabel): Promise<LabelImportResult> => {
    if (mode === ConfigImportMode.Add) {
      return refused('failed', 'exists', 'Label already exists', true, parsed.data);
    }
    if (!color || color.toLowerCase() === label.color?.toLowerCase()) {
      return refused('skipped', 'unchanged', 'Already up to date', true, parsed.data);
    }
    if (!dryRun) {
      await labelEditField(context, user, label.id, [{ key: 'color', value: [color] }]);
    }
    return { status: 'overwritten', exists: true, configuration: parsed.data };
  };
  if (existing) {
    return importExisting(existing);
  }
  if (!dryRun) {
    // addLabel gives a label without color the one it makes of its value
    const added = await addLabel(context, user, { value, color });
    // addLabel returns the label as it is when another one was created since the lookup above: it is an existing label.
    // Known limitation, left as it is: a label created by someone else between the lookup of addLabel and its write is upserted by the
    // generic create path (with the color given, else the generated one) and reported as created. Fixing it needs a create-only creation in the middleware.
    if (color && added.color?.toLowerCase() !== color.toLowerCase()) {
      return importExisting(added);
    }
  }
  return { status: 'created', exists: false, configuration: parsed.data };
};
