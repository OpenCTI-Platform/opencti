import { Readable } from 'node:stream';
import { normalizeName } from '../../schema/identifier';
import type { EditInput } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { configImportReasonValue, configImportValidationReason, freeConfigImportName } from '../configImport/configImport-utils';
import { addExclusionListFile, exclusionListStorageKey, fieldPatchExclusionList, findExclusionListsByName, MAX_FILE_SIZE } from './exclusionList-domain';
import { readExclusionListFile } from './exclusionList-file';
import { type ExclusionListImportConfiguration, exclusionListImportSchema } from './exclusionList-import-schema';
import { hasSameTypes } from './exclusionList-rules';

export type ExclusionListImportCode = 'invalid' | 'exists' | 'name_conflict' | 'unchanged' | 'ambiguous' | 'duplicate' | 'file_missing' | 'file_too_large' | 'file_not_own';

export interface ExclusionListImportOptions extends ConfigImportOptions {
  // The names (normalized) the items of the same import already hold: two lists of a bundle with the same name are one list on the platform
  reservedNames?: Set<string>;
}

export type ExclusionListImportResult = ConfigImportResult<ExclusionListImportConfiguration, ExclusionListImportCode>;

// The file of the values of the list, read when it is needed: null when it is bigger than the limit
export interface ExclusionListImportFile {
  read: (limit: number) => Promise<Buffer | null>;
}

const refused = (
  status: 'failed' | 'skipped',
  code: ExclusionListImportCode,
  reason: string,
  exists: boolean,
  configuration?: ExclusionListImportConfiguration,
): ExclusionListImportResult => ({ status, code, reason, exists, configuration });

// The values in the form the domain takes an upload: the platform checks the type from the name of the file
const toUpload = (content: Buffer) => {
  return { createReadStream: () => Readable.from(content), filename: 'exclusion-list.txt', mimeType: 'text/plain' };
};

// The one place where an exclusion list is imported: validates, finds the list by its name and writes it with its values file.
// A refusal is a result, not an error. A dry run decides the same result and writes nothing.
// The standard id of an exclusion list is random: it is found by its name (without its case), and several lists of the same name are
// refused, not guessed. The values are the file of the bundle, written by the domain (which checks it, counts its lines and has the
// cache rebuilt): the list is never written any other way.
// add: the list must not exist yet. overwrite: a list that exists is given the type, the state and the description of the configuration
// (a description that is null or absent, and a state that is absent, leave it untouched) and the values of the file when they differ.
// copy: a list is its name, so the copy of one that exists is another list under the first free `name (n)` (a name the platform or an
// earlier item of the bundle holds is taken), with the values of the file, whatever the lists that already have its name.
export const importExclusionList = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  file: ExclusionListImportFile | undefined,
  { mode, dryRun = false, reservedNames }: ExclusionListImportOptions,
): Promise<ExclusionListImportResult> => {
  const parsed = exclusionListImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('failed', 'invalid', configImportValidationReason(parsed.error), false);
  }
  const { name, description, enabled, exclusion_list_entity_types: types } = parsed.data;
  // Found by name, a second list of the bundle with the same name would overwrite the first one
  if (reservedNames?.has(normalizeName(name))) {
    return refused('failed', 'duplicate', 'Another exclusion list of the bundle has this name', false, parsed.data);
  }
  reservedNames?.add(normalizeName(name));
  const sameName = await findExclusionListsByName(context, user, name);
  const isCopy = mode === ConfigImportMode.Copy;
  // A copy is never refused for the lists that have its name, however many: it does not touch any of them
  if (sameName.length > 1 && !isCopy) {
    return refused('failed', 'ambiguous', 'Several exclusion lists have this name', true, parsed.data);
  }
  const [existing] = sameName;
  if (existing && mode === ConfigImportMode.Add) {
    return refused('failed', 'exists', 'Exclusion list already exists', true, parsed.data);
  }
  // The values of a list are read and written under its own key: a list that points at another file is not touched, whatever the bundle holds
  if (!isCopy && existing && existing.file_id !== exclusionListStorageKey(existing.internal_id)) {
    return refused('failed', 'file_not_own', 'The file of the exclusion list is not its own', true, parsed.data);
  }
  if (!file) {
    return refused('failed', 'file_missing', 'The file of the values of the exclusion list is missing from the bundle', !!existing, parsed.data);
  }
  const content = await file.read(MAX_FILE_SIZE);
  if (!content) {
    return refused('failed', 'file_too_large', 'The file of the values of the exclusion list is too large', !!existing, parsed.data);
  }
  if (!existing || isCopy) {
    const copyName = isCopy
      ? await freeConfigImportName(name, async (candidate) => {
          const heldByBundle = candidate !== name && !!reservedNames?.has(normalizeName(candidate));
          return heldByBundle || (await findExclusionListsByName(context, user, candidate)).length > 0;
        })
      : name;
    if (!copyName) {
      return refused('failed', 'name_conflict', 'Exclusion list already exists', !!existing, parsed.data);
    }
    reservedNames?.add(normalizeName(copyName));
    if (!dryRun) {
      await addExclusionListFile(context, user, {
        name: copyName,
        description: description ?? undefined,
        exclusion_list_entity_types: types,
        file: toUpload(content),
      }, enabled !== false);
    }
    const reason = copyName === name ? undefined : `Added as "${configImportReasonValue(copyName)}"`;
    return { status: 'created', exists: !!existing, configuration: parsed.data, reason };
  }
  const patch: EditInput[] = [];
  if (description !== null && description !== undefined && description !== (existing.description ?? '')) {
    patch.push({ key: 'description', value: [description] });
  }
  if (enabled !== undefined && enabled !== existing.enabled) {
    patch.push({ key: 'enabled', value: [String(enabled)] });
  }
  if (!hasSameTypes(existing.exclusion_list_entity_types, types)) {
    patch.push({ key: 'exclusion_list_entity_types', value: types });
  }
  // The size tells two files apart for free, the bytes of the stored file are read only when the sizes are the same
  const stored = existing.exclusion_list_file_size === content.length ? await readExclusionListFile(existing) : null;
  const hasNewValues = !stored || !stored.equals(content);
  if (patch.length === 0 && !hasNewValues) {
    return refused('skipped', 'unchanged', 'Already up to date', true, parsed.data);
  }
  if (!dryRun) {
    await fieldPatchExclusionList(context, user, { id: existing.id, input: patch, file: hasNewValues ? toUpload(content) : undefined });
  }
  return { status: 'overwritten', exists: true, configuration: parsed.data };
};
