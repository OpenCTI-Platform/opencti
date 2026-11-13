import { Readable } from 'node:stream';
import { FilterMode, FilterOperator, type EditInput } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import { fullEntitiesList, storeLoadById } from '../../database/middleware-loader';
import type { FileUploadData } from '../../database/file-storage';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { CONFIG_IMPORT_UNCHANGED_REASON, configImportReasonValue, configImportValidationReason, freeConfigImportName } from '../configImport/configImport-utils';
import { logApp } from '../../config/conf';
import { addFintelDesign, fintelDesignDelete, fintelDesignEditField } from './fintelDesign-domain';
import { FINTEL_DESIGN_NAME_MAX_LENGTH, type FintelDesignImportConfiguration, fintelDesignImportSchema } from './fintelDesign-import-schema';
import { FINTEL_DESIGN_LOGO_MAX_SIZE, fintelDesignLogoExtension, fintelDesignLogoStorageKey, isCompleteFintelDesignLogo, readFintelDesignLogo } from './fintelDesign-logo';
import { type BasicStoreEntityFintelDesign, ENTITY_TYPE_FINTEL_DESIGN } from './fintelDesign-types';

export type FintelDesignImportCode = 'invalid' | 'exists' | 'name_conflict' | 'unchanged' | 'logo_too_large' | 'logo_invalid';

export interface FintelDesignImportOptions extends ConfigImportOptions {
  // A dry run writes nothing: the names the earlier items of the same dry run would give (a copy, a creation, a rename) are reserved for the next ones
  reservedNames?: Set<string>;
  // The ids of the designs an earlier item of the same dry run renames: the name they have now is no longer theirs.
  // Ids and not names: two designs can have the same name, and the other one keeps it
  renamedIds?: Set<string>;
}

// The logo of the design, read when it is needed: null when it is bigger than the limit
export interface FintelDesignImportLogo {
  read: (limit: number) => Promise<Buffer | null>;
}

export type FintelDesignImportResult = ConfigImportResult<FintelDesignImportConfiguration, FintelDesignImportCode> & {
  // The name of a copy: the one of the configuration, or the free one it takes when the design exists
  copyName?: string;
};

const COLOR_FIELDS = ['gradiantFromColor', 'gradiantToColor', 'textColor'] as const;

const refused = (
  status: 'failed' | 'skipped',
  code: FintelDesignImportCode,
  reason: string,
  exists: boolean,
  configuration?: FintelDesignImportConfiguration,
): FintelDesignImportResult => ({ status, code, reason, exists, configuration });

// The logo in the form the domain takes an upload: the domain checks that it is an image from the extension of its name
const toLogoUpload = ({ content, extension }: { content: Buffer; extension: string }): Promise<FileUploadData> => {
  return Promise.resolve({ createReadStream: () => Readable.from(content), filename: `logo.${extension}` });
};

const isNameTaken = async (context: AuthContext, user: AuthUser, name: string, { reservedNames, renamedIds }: FintelDesignImportOptions) => {
  if (reservedNames?.has(name)) {
    return true;
  }
  const filters = { mode: FilterMode.And, filters: [{ key: ['name'], values: [name], operator: FilterOperator.Eq }], filterGroups: [] };
  const designs = await fullEntitiesList<BasicStoreEntityFintelDesign>(context, user, [ENTITY_TYPE_FINTEL_DESIGN], { filters });
  return designs.some((design) => design.name === name && !renamedIds?.has(design.id));
};

// The stored logo of the design is the one of the bundle: an unreadable stored logo is replaced
const hasSameLogo = async (existing: BasicStoreEntityFintelDesign, content: Buffer) => {
  if (existing.file_id !== fintelDesignLogoStorageKey(existing.internal_id)) {
    return false;
  }
  const stored = await readFintelDesignLogo(existing).catch(() => null);
  return !!stored && stored.equals(content);
};

const findDefaultFintelDesignId = async (context: AuthContext, user: AuthUser) => {
  const filters = { mode: FilterMode.And, filters: [{ key: ['default'], values: [true as unknown as string], operator: FilterOperator.Eq }], filterGroups: [] };
  const [defaultDesign] = await fullEntitiesList<BasicStoreEntityFintelDesign>(context, user, [ENTITY_TYPE_FINTEL_DESIGN], { filters });
  return defaultDesign?.id;
};

// A design created by an item that fails is undone, so that the platform is as it was before the item. The edit that failed may have got
// as far as making the design the default, taking the default away from the previous one: the previous one is made the default again
// first, which takes it away from the design, and the design is deleted only then. When that fails, the design stays: a design left as
// the default is better than a platform without one.
const undoFintelDesignCreation = async (context: AuthContext, user: AuthUser, createdId: string, previousDefaultId: string | undefined) => {
  try {
    const created = await storeLoadById<BasicStoreEntityFintelDesign>(context, user, createdId, ENTITY_TYPE_FINTEL_DESIGN);
    if (created?.default === true && previousDefaultId) {
      await fintelDesignEditField(context, user, { id: previousDefaultId, input: [{ key: 'default', value: [true] }] });
    }
    await fintelDesignDelete(context, user, createdId);
  } catch (undoError) {
    logApp.error('[CONFIG PRESET] A fintel design created by an item that failed could not be undone', { id: createdId, previousDefaultId, cause: undoError });
  }
};

const createFintelDesign = async (
  context: AuthContext,
  user: AuthUser,
  design: Omit<FintelDesignImportConfiguration, 'standard_id'>,
  logo: { content: Buffer; extension: string } | undefined,
  standardId?: string,
) => {
  const isDefault = design.default === true;
  // The logo is stored under the internal id of the design: it is written once the design exists. Until it is, the design is not the
  // default: the logo and the default are written by one edit, which stores the logo before it changes anything
  const created = await addFintelDesign(context, user, {
    name: design.name,
    description: design.description ?? undefined,
    gradiantFromColor: design.gradiantFromColor ?? undefined,
    gradiantToColor: design.gradiantToColor ?? undefined,
    textColor: design.textColor ?? undefined,
    default: isDefault && !logo,
    ...(standardId ? { standard_id: standardId } : {}),
  });
  if (logo) {
    // Read before the edit: the default the platform goes back to when the item fails
    const previousDefaultId = isDefault ? await findDefaultFintelDesignId(context, user) : undefined;
    try {
      await fintelDesignEditField(context, user, { id: created.id, file: toLogoUpload(logo), input: isDefault ? [{ key: 'default', value: [true] }] : [] });
    } catch (error) {
      // The item fails as a whole, with the error of the edit, whatever the undo does
      await undoFintelDesignCreation(context, user, created.id, previousDefaultId);
      throw error;
    }
  }
};

// The one place where a fintel design is imported: validates, finds the design by its standard id and writes it with its logo.
// A refusal is a result, not an error. A dry run decides the same result and writes nothing.
// add: the design must not exist yet. overwrite: a design with the same standard id is patched, else it is created.
// copy: the design is created, under a free name and a new standard id when its own exists.
// The default design of the bundle becomes the default of the platform, a copy included: as in the UI, the domain then takes the default
// away from the previous one, so the platform keeps exactly one. `default: false` is never written: the previous default loses it only
// because another one is set, so the platform never ends up without a default.
// A value that is null or absent is left untouched, and so is the logo when the bundle has none.
export const importFintelDesign = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  logoFile: FintelDesignImportLogo | undefined,
  options: FintelDesignImportOptions,
): Promise<FintelDesignImportResult> => {
  const { mode, dryRun = false, reservedNames, renamedIds } = options;
  const parsed = fintelDesignImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('failed', 'invalid', configImportValidationReason(parsed.error), false);
  }
  const { standard_id: standardId, ...design } = parsed.data;
  const existing = await storeLoadById<BasicStoreEntityFintelDesign>(context, user, standardId, ENTITY_TYPE_FINTEL_DESIGN);
  if (existing && mode === ConfigImportMode.Add) {
    return refused('failed', 'exists', 'Fintel design already exists', true, parsed.data);
  }
  let logo: { content: Buffer; extension: string } | undefined;
  if (logoFile) {
    const content = await logoFile.read(FINTEL_DESIGN_LOGO_MAX_SIZE);
    if (!content) {
      return refused('failed', 'logo_too_large', 'The logo of the fintel design is too large', !!existing, parsed.data);
    }
    // The format is recognized from the first bytes, and the logo must go on to the end of it: a logo cut short is stored, but a browser
    // cannot show it, and the reports of the design cannot be generated
    const extension = fintelDesignLogoExtension(content);
    if (!extension || !isCompleteFintelDesignLogo(content, extension)) {
      return refused('failed', 'logo_invalid', 'The logo of the fintel design is not a supported image', !!existing, parsed.data);
    }
    logo = { content, extension };
  }
  // A copy of a design that exists is another design: a new standard id, and a free name to tell them apart
  if (mode === ConfigImportMode.Copy) {
    const name = existing
      ? await freeConfigImportName(design.name, (candidate) => isNameTaken(context, user, candidate, options), { maxLength: FINTEL_DESIGN_NAME_MAX_LENGTH })
      : design.name;
    if (!name) {
      return refused('failed', 'name_conflict', 'Fintel design name already exists', !!existing, parsed.data);
    }
    reservedNames?.add(name);
    const reason = name === design.name ? undefined : `Added as "${configImportReasonValue(name)}"`;
    const copy: FintelDesignImportResult = { status: 'created', exists: !!existing, configuration: parsed.data, copyName: name, reason };
    if (!dryRun) {
      await createFintelDesign(context, user, { ...design, name }, logo, existing ? undefined : standardId);
    }
    return copy;
  }
  if (!existing) {
    reservedNames?.add(design.name);
    if (!dryRun) {
      await createFintelDesign(context, user, design, logo, standardId);
    }
    return { status: 'created', exists: false, configuration: parsed.data };
  }
  const patch: EditInput[] = [];
  if (design.name !== existing.name) {
    patch.push({ key: 'name', value: [design.name] });
  }
  if (design.description !== null && design.description !== undefined && design.description !== (existing.description ?? '')) {
    patch.push({ key: 'description', value: [design.description] });
  }
  COLOR_FIELDS.forEach((field) => {
    const value = design[field];
    if (value !== null && value !== undefined && value !== (existing[field] ?? '')) {
      patch.push({ key: field, value: [value] });
    }
  });
  if (design.default === true && existing.default !== true) {
    patch.push({ key: 'default', value: [true] });
  }
  const hasNewLogo = !!logo && !(await hasSameLogo(existing, logo.content));
  if (patch.length === 0 && !hasNewLogo) {
    return refused('skipped', 'unchanged', CONFIG_IMPORT_UNCHANGED_REASON, true, parsed.data);
  }
  reservedNames?.add(design.name);
  if (design.name !== existing.name) {
    renamedIds?.add(existing.id);
  }
  if (!dryRun) {
    await fintelDesignEditField(context, user, { id: existing.id, input: patch, file: hasNewLogo && logo ? toLogoUpload(logo) : undefined });
  }
  return { status: 'overwritten', exists: true, configuration: parsed.data };
};
