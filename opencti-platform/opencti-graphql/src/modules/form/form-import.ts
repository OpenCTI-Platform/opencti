import { isDeepStrictEqual } from 'node:util';
import { FilterMode } from '../../generated/graphql';
import { normalizeName } from '../../schema/identifier';
import type { AuthContext, AuthUser } from '../../types/user';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import {
  CONFIG_IMPORT_UNCHANGED_REASON,
  configImportReasonValue,
  configImportRefusal,
  configImportValidationReason,
  freeConfigImportName,
  joinConfigImportReasons,
} from '../configImport/configImport-utils';
import { addForm, findAllForms, formEditField, formSchemaErrors } from './form-domain';
import { convertFormSchemaIds } from './form-export';
import { type FormIntakeImportConfiguration, formIntakeImportSchema } from './form-import-schema';
import type { BasicStoreEntityForm, FormSchemaDefinition } from './form-types';

export type FormIntakeImportCode = 'invalid' | 'ambiguous' | 'duplicate' | 'name_conflict' | 'unchanged';

export interface FormIntakeImportOptions extends ConfigImportOptions {
  // The names (normalized) with their main entity type the items of the same import already hold: two forms of a bundle with the same name and
  // type are one form on the platform
  reservedKeys?: Set<string>;
}

export type FormIntakeImportResult = ConfigImportResult<FormIntakeImportConfiguration, FormIntakeImportCode>;

// What the import leaves out of a form: the groups and the markings the platform does not know. The users and the organizations are never exported.
export const FORM_INTAKE_UNRESOLVED_REASON = 'Groups or markings not found are left out of the form';

// The name as the platform tells two forms apart: the lookup by name also ignores the case and the accents
const reservationKey = (name: string, entityType: string) => `${normalizeName(name).normalize('NFD').replace(/\p{Diacritic}/gu, '')}|${entityType}`;

// The forms of a name and a main entity type: the identity of a form, the one addForm checks
const findFormsByNameAndType = async (context: AuthContext, user: AuthUser, name: string, entityType: string): Promise<BasicStoreEntityForm[]> => {
  return findAllForms(context, user, {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['name'], values: [name] }, { key: ['main_entity_type'], values: [entityType] }],
      filterGroups: [],
    },
  });
};

const hasSameSchema = (stored: string, schema: FormSchemaDefinition) => {
  try {
    return isDeepStrictEqual(JSON.parse(stored), schema);
  } catch {
    return false;
  }
};

// The one place where a form intake is imported: validates, finds the form by its name and its main entity type, and writes it through the domain
// (the ingestion connector of the form is registered by it). A refusal is a result, not an error. A dry run decides the same result and writes nothing.
// The standard id of a form is random: the form is found by its name and its main entity type, and several forms with them are refused, not guessed.
// The groups and the markings of the schema are the ones of the platform, found by standard id: what it does not know is left out of the form.
// A form is created inactive, whatever it was: it has to be checked, and what named a user or an organization is empty.
// overwrite: a form that exists is given the description and the schema of the configuration, and is set inactive (when it changes) like a new
// one: it has to be checked again. A form that is already as the bundle has it is left as it is.
// copy: a form is its name, so the copy of one that exists is another form under the first free `name (n)`.
export const importFormIntake = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { mode, dryRun = false, reservedKeys }: FormIntakeImportOptions,
): Promise<FormIntakeImportResult> => {
  const parsed = formIntakeImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return configImportRefusal('failed', 'invalid', configImportValidationReason(parsed.error), false);
  }
  const { name, description, form_schema: rawSchema } = parsed.data;
  const schemaError = formSchemaErrors(rawSchema);
  if (schemaError) {
    return configImportRefusal('failed', 'invalid', configImportReasonValue(`form_schema: ${schemaError}`), false, parsed.data);
  }
  const formSchema = rawSchema as unknown as FormSchemaDefinition;
  const entityType = formSchema.mainEntityType;
  // The entity type is not checked: a form for a type the platform does not have (yet) is imported, and works once the type exists
  const isCopy = mode === ConfigImportMode.Copy;
  // A copy overwrites nothing: it only reserves the name it is given below
  if (!isCopy) {
    if (reservedKeys?.has(reservationKey(name, entityType))) {
      return configImportRefusal('failed', 'duplicate', 'Another form intake of the bundle has this name', false, parsed.data);
    }
    reservedKeys?.add(reservationKey(name, entityType));
  }
  const sameName = await findFormsByNameAndType(context, user, name, entityType);
  // A copy is never refused for the forms that have its name, however many: it does not touch any of them
  if (sameName.length > 1 && !isCopy) {
    return configImportRefusal('failed', 'ambiguous', 'Several form intakes have this name', true, parsed.data);
  }
  const [existing] = sameName;
  const { schema, unresolved } = await convertFormSchemaIds(context, user, formSchema, 'stix');
  const warningReason = unresolved > 0 ? FORM_INTAKE_UNRESOLVED_REASON : undefined;
  if (!existing || isCopy) {
    const copyName = isCopy
      ? await freeConfigImportName(name, async (candidate) => {
          // A name given to an earlier copy of the bundle is taken, including the name of this form: a copy does not reserve its source name
          return !!reservedKeys?.has(reservationKey(candidate, entityType)) || (await findFormsByNameAndType(context, user, candidate, entityType)).length > 0;
        })
      : name;
    if (!copyName) {
      return configImportRefusal('failed', 'name_conflict', 'Form intake already exists', !!existing, parsed.data);
    }
    reservedKeys?.add(reservationKey(copyName, entityType));
    if (!dryRun) {
      await addForm(context, user, { name: copyName, description: description ?? '', form_schema: JSON.stringify(schema), active: false });
    }
    const copyReason = copyName === name ? undefined : `Added as "${configImportReasonValue(copyName)}"`;
    return { status: 'created', exists: !!existing, configuration: parsed.data, reason: joinConfigImportReasons([copyReason, warningReason]) };
  }
  const patch: { key: string; value: string[] }[] = [];
  if (description !== null && description !== undefined && description !== (existing.description ?? '')) {
    patch.push({ key: 'description', value: [description] });
  }
  if (!hasSameSchema(existing.form_schema, schema)) {
    patch.push({ key: 'form_schema', value: [JSON.stringify(schema)] });
  }
  if (patch.length === 0) {
    return configImportRefusal('skipped', 'unchanged', CONFIG_IMPORT_UNCHANGED_REASON, true, parsed.data);
  }
  // The form changes: it is set inactive (its ingestion connector is stopped by formEditField) until someone has checked it
  if (existing.active) {
    patch.push({ key: 'active', value: ['false'] });
  }
  if (!dryRun) {
    await formEditField(context, user, existing.id, patch);
  }
  return { status: 'overwritten', exists: true, configuration: parsed.data, reason: warningReason };
};
