import type { FileHandle } from 'fs/promises';
import { FunctionalError } from '../../config/errors';
import type { EditInput } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { configImportValidationReason } from '../configImport/configImport-utils';
import { extractContentFrom } from '../../utils/fileToContent';
import { BUILT_IN_THEME_STANDARD_IDS } from './theme-constants';
import { addTheme, checkExistingTheme, fieldPatchTheme, findById } from './theme-domain';
import { THEME_NAME_MAX_LENGTH, type ThemeImportConfiguration, themeImportSchema } from './theme-import-schema';

// A dry run writes nothing: the names the earlier items of the same dry run would take are reserved for the next ones
export interface ThemeImportOptions extends ConfigImportOptions {
  reservedNames?: Set<string>;
  // The names that a theme overwritten earlier in a dry run no longer holds, as the real import would have renamed it already
  releasedNames?: Set<string>;
}

export type ThemeImportCode = 'invalid' | 'standard_id_required' | 'exists' | 'name_conflict' | 'built_in';

// add: the theme must not exist yet. overwrite: a theme with the same standard id is patched, else it is created.
// copy: the theme is created under a free name, and a new standard id when its own exists.
export type ThemeImportResult = ConfigImportResult<ThemeImportConfiguration, ThemeImportCode> & {
  // The theme written, absent on a dry run
  theme?: Awaited<ReturnType<typeof addTheme>>;
};

const refused = (status: 'failed' | 'skipped', code: ThemeImportCode, reason: string, exists: boolean, configuration?: ThemeImportConfiguration): ThemeImportResult => {
  return { status, code, reason, exists, configuration };
};

const MAX_COPIES = 100;

// The name itself when it is free, else the first free `name (n)`; undefined when the first copies are all taken
// Taken by a theme of the platform, or by one that a dry run would have created; not by one that a dry run would have renamed
const isNameTaken = async (context: AuthContext, user: AuthUser, name: string, { reservedNames, releasedNames }: ThemeImportOptions, excludeId?: string) => {
  return !!reservedNames?.has(name) || (!releasedNames?.has(name) && await checkExistingTheme(context, user, name, excludeId));
};

const freeThemeName = async (context: AuthContext, user: AuthUser, name: string, options: ThemeImportOptions) => {
  const isTaken = (candidate: string) => isNameTaken(context, user, candidate, options);
  if (!(await isTaken(name))) {
    return name;
  }
  for (let copy = 1; copy <= MAX_COPIES; copy += 1) {
    const suffix = ` (${copy})`;
    const candidate = `${name.slice(0, THEME_NAME_MAX_LENGTH - suffix.length)}${suffix}`;
    // The next candidate depends on this answer
    if (!(await isTaken(candidate))) {
      return candidate;
    }
  }
  return undefined;
};

// addTheme trusts its input: the standard id is the given one (absent: the platform gives one), and the theme is never built-in
const createTheme = (context: AuthContext, user: AuthUser, theme: Omit<ThemeImportConfiguration, 'standard_id'>, standardId?: string) => {
  return addTheme(context, user, {
    ...theme,
    theme_logo: theme.theme_logo ?? '',
    theme_logo_collapsed: theme.theme_logo_collapsed ?? '',
    theme_logo_login: theme.theme_logo_login ?? '',
    ...(standardId ? { standard_id: standardId } : {}),
    built_in: false,
  });
};

// The one place where a theme is imported: validates, applies the rules of a theme (built-in, name, identity) and writes it.
// A dry run decides the same result without writing anything. A refusal is a result, not an error.
export const importTheme = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  options: ThemeImportOptions,
): Promise<ThemeImportResult> => {
  const { mode, dryRun = false, reservedNames, releasedNames } = options;
  const parsed = themeImportSchema.safeParse(configuration);
  // A built-in theme has the same standard id on every platform: never patched, never created, and never refused for its content
  // (the id is read before the validation: a bundle may carry the name only)
  const givenStandardId = (configuration as { standard_id?: unknown } | null)?.standard_id;
  if (typeof givenStandardId === 'string' && Object.values(BUILT_IN_THEME_STANDARD_IDS).includes(givenStandardId)) {
    return refused('skipped', 'built_in', 'Built-in theme', true, parsed.success ? parsed.data : undefined);
  }
  if (!parsed.success) {
    return refused('failed', 'invalid', configImportValidationReason(parsed.error), false);
  }
  const { standard_id: standardId, ...theme } = parsed.data;
  if (mode === ConfigImportMode.Overwrite && !standardId) {
    return refused('failed', 'standard_id_required', 'The standard id of the theme is required to overwrite it', false, parsed.data);
  }
  const existing = standardId ? await findById(context, user, standardId) : undefined;
  if (existing?.built_in) {
    return refused('skipped', 'built_in', 'Built-in theme', true, parsed.data);
  }
  if (existing && mode === ConfigImportMode.Add) {
    return refused('failed', 'exists', 'Theme already exists', true, parsed.data);
  }
  // A copy is never refused for its name or its identity: it takes a free name, and a new standard id when its own is taken
  if (mode === ConfigImportMode.Copy) {
    const name = await freeThemeName(context, user, theme.name, options);
    if (!name) {
      return refused('failed', 'name_conflict', 'Theme name already exists', !!existing, parsed.data);
    }
    const copy: ThemeImportResult = { status: 'created', exists: !!existing, configuration: parsed.data, reason: name === theme.name ? undefined : `Added as "${name}"` };
    if (dryRun) {
      reservedNames?.add(name);
      return copy;
    }
    return { ...copy, theme: await createTheme(context, user, { ...theme, name }, existing ? undefined : standardId) };
  }
  // The theme itself is not another theme: an overwrite that renames it to a name used by a third one is refused too
  if (await isNameTaken(context, user, theme.name, options, existing?.id)) {
    return refused('failed', 'name_conflict', 'Theme name already exists', !!existing, parsed.data);
  }
  const status = existing ? 'overwritten' : 'created';
  if (dryRun) {
    reservedNames?.add(theme.name);
    if (existing && existing.name !== theme.name) {
      releasedNames?.add(existing.name);
    }
    return { status, exists: !!existing, configuration: parsed.data };
  }
  if (existing) {
    // A value that is null or absent is left untouched
    const input: EditInput[] = Object.entries(theme)
      .filter(([, value]) => value !== null && value !== undefined)
      .map(([key, value]) => ({ key, value: [value as string] }));
    return { status, exists: true, configuration: parsed.data, theme: await fieldPatchTheme(context, user, existing.id, input) };
  }
  return { status, exists: false, configuration: parsed.data, theme: await createTheme(context, user, theme, standardId) };
};

const importError = ({ code, reason }: ThemeImportResult, name?: string) => {
  switch (code) {
    case 'invalid':
      return FunctionalError('Invalid theme file', { reason });
    case 'name_conflict':
      return FunctionalError('Theme name already exists', { name });
    default:
      return FunctionalError(reason ?? 'Theme cannot be imported');
  }
};

// The import of a theme file: the theme must not exist yet
export const themeImport = async (context: AuthContext, user: AuthUser, file: Promise<FileHandle>) => {
  const content = await extractContentFrom(file);
  const result = await importTheme(context, user, content, { mode: ConfigImportMode.Add });
  if (result.status !== 'created') {
    throw importError(result, result.configuration?.name);
  }
  return result.theme!;
};
