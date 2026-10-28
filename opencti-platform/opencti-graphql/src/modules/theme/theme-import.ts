import type { FileHandle } from 'fs/promises';
import { FunctionalError } from '../../config/errors';
import type { EditInput } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import type { ConfigImportOptions, ConfigImportResult } from '../configImport/configImport-types';
import { extractContentFrom } from '../../utils/fileToContent';
import { BUILT_IN_THEME_STANDARD_IDS } from './theme-constants';
import { addTheme, checkExistingTheme, fieldPatchTheme, findById } from './theme-domain';
import { type ThemeImportConfiguration, themeImportSchema } from './theme-import-schema';

export type ThemeImportCode = 'invalid' | 'standard_id_required' | 'exists' | 'name_conflict' | 'built_in';

// add: the theme must not exist yet. overwrite: a theme with the same standard id is patched, else it is created.
export type ThemeImportResult = ConfigImportResult<ThemeImportConfiguration, ThemeImportCode> & {
  // The theme written, absent on a dry run
  theme?: Awaited<ReturnType<typeof addTheme>>;
};

const refused = (status: 'failed' | 'skipped', code: ThemeImportCode, reason: string, exists: boolean, configuration?: ThemeImportConfiguration): ThemeImportResult => {
  return { status, code, reason, exists, configuration };
};

const validationReason = (issues: { path: PropertyKey[]; message: string }[]) => {
  return issues.map((issue) => `${issue.path.map(String).join('.') || 'configuration'}: ${issue.message}`).join(', ');
};

// The one place where a theme is imported: validates, applies the rules of a theme (built-in, name, identity) and writes it.
// A dry run decides the same result without writing anything. A refusal is a result, not an error.
export const importTheme = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { mode, dryRun = false }: ConfigImportOptions,
): Promise<ThemeImportResult> => {
  const parsed = themeImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('failed', 'invalid', validationReason(parsed.error.issues), false);
  }
  const { standard_id: standardId, ...theme } = parsed.data;
  // A built-in theme has the same standard id on every platform: never patched, never created
  if (standardId && Object.values(BUILT_IN_THEME_STANDARD_IDS).includes(standardId)) {
    return refused('skipped', 'built_in', 'Built-in theme', true, parsed.data);
  }
  if (mode === 'overwrite' && !standardId) {
    return refused('failed', 'standard_id_required', 'The standard id of the theme is required to overwrite it', false, parsed.data);
  }
  const existing = standardId ? await findById(context, user, standardId) : undefined;
  if (existing?.built_in) {
    return refused('skipped', 'built_in', 'Built-in theme', true, parsed.data);
  }
  if (existing && mode === 'add') {
    return refused('failed', 'exists', 'Theme already exists', true, parsed.data);
  }
  // The theme itself is not another theme: an overwrite that renames it to a name used by a third one is refused too
  if (await checkExistingTheme(context, user, theme.name, existing?.id)) {
    return refused('failed', 'name_conflict', 'Theme name already exists', !!existing, parsed.data);
  }
  const status = existing ? 'overwritten' : 'created';
  if (dryRun) {
    return { status, exists: !!existing, configuration: parsed.data };
  }
  if (existing) {
    // A value that is null or absent is left untouched
    const input: EditInput[] = Object.entries(theme)
      .filter(([, value]) => value !== null && value !== undefined)
      .map(([key, value]) => ({ key, value: [value as string] }));
    return { status, exists: true, configuration: parsed.data, theme: await fieldPatchTheme(context, user, existing.id, input) };
  }
  // addTheme trusts its input: the standard id is the one of the configuration, and the theme is never built-in
  const created = await addTheme(context, user, {
    ...theme,
    theme_logo: theme.theme_logo ?? '',
    theme_logo_collapsed: theme.theme_logo_collapsed ?? '',
    theme_logo_login: theme.theme_logo_login ?? '',
    ...(standardId ? { standard_id: standardId } : {}),
    built_in: false,
  });
  return { status, exists: false, configuration: parsed.data, theme: created };
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
  const result = await importTheme(context, user, content, { mode: 'add' });
  if (result.status !== 'created') {
    throw importError(result, result.configuration?.name);
  }
  return result.theme!;
};
