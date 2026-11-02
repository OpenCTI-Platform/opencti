import type { z } from 'zod';
import { getSettings, settingsEditField } from '../../domain/settings';
import type { AuthContext, AuthUser } from '../../types/user';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { configImportValidationReason } from '../configImport/configImport-utils';
import { findById as findThemeById } from '../theme/theme-domain';
import { SETTINGS_MESSAGES_FIELDS, SETTINGS_PLATFORM_FIELDS } from './settings-export';
import { messageConfigurationSchemas, platformConfigurationSchema } from './settings-import-schema';

export type SettingsImportCode = 'invalid' | 'unknown_message' | 'not_overwrite' | 'nothing_to_import' | 'default_theme_missing';

export type SettingsImportResult<TConfiguration = Record<string, unknown>> = ConfigImportResult<TConfiguration, SettingsImportCode>;

// The same import of the same item, with an option the settings do not know of: what a dry run accepts that a real import cannot yet
export interface PlatformImportOptions extends ConfigImportOptions {
  // A dry run accepts a default theme that does not exist yet when the same import creates it
  isThemeCreated?: (standardId: string) => boolean;
}

// The settings always exist and have no copy: only an overwrite writes them, any other mode leaves them as they are
const skipped = (code: SettingsImportCode, reason: string, configuration?: Record<string, unknown>): SettingsImportResult => {
  return { status: 'skipped', code, reason, exists: true, configuration };
};

const failed = (code: SettingsImportCode, reason: string, configuration?: Record<string, unknown>): SettingsImportResult => {
  return { status: 'failed', code, reason, exists: true, configuration };
};

const isNothingToImport = (configuration: Record<string, unknown>, keys: string[]) => {
  return keys.every((key) => configuration[key] === null || configuration[key] === undefined);
};

// A value that is null or absent is left untouched
const toInput = (configuration: Record<string, unknown>, keys: string[]) => {
  return keys
    .filter((key) => configuration[key] !== null && configuration[key] !== undefined)
    .map((key) => ({ key, value: [configuration[key]] }));
};

const writeSettings = async (context: AuthContext, user: AuthUser, input: { key: string; value: unknown[] }[]) => {
  await settingsEditField(context, user, (await getSettings(context)).id, input);
};

// The rules of a setting that is only a few fields of the Settings: validates, decides, and writes the fields that are set with one call
const importFields = async (
  context: AuthContext,
  user: AuthUser,
  schema: z.ZodType<Record<string, unknown>>,
  keys: string[],
  configuration: unknown,
  { mode, dryRun = false }: ConfigImportOptions,
): Promise<SettingsImportResult> => {
  const parsed = schema.safeParse(configuration);
  if (!parsed.success) {
    return failed('invalid', configImportValidationReason(parsed.error));
  }
  if (mode !== ConfigImportMode.Overwrite) {
    return skipped('not_overwrite', 'Already exists', parsed.data);
  }
  if (isNothingToImport(parsed.data, keys)) {
    return skipped('nothing_to_import', 'Nothing to import', parsed.data);
  }
  if (!dryRun) {
    await writeSettings(context, user, toInput(parsed.data, keys));
  }
  return { status: 'overwritten', exists: true, configuration: parsed.data };
};

// A message is one of the own keys of SETTINGS_MESSAGES_FIELDS: the id comes from a bundle, `constructor` is not a message
export const importMessage = (context: AuthContext, user: AuthUser, messageId: string, configuration: unknown, options: ConfigImportOptions) => {
  if (!Object.hasOwn(SETTINGS_MESSAGES_FIELDS, messageId)) {
    return Promise.resolve(failed('unknown_message', 'Unknown message'));
  }
  const id = messageId as keyof typeof SETTINGS_MESSAGES_FIELDS;
  return importFields(context, user, messageConfigurationSchemas[id], SETTINGS_MESSAGES_FIELDS[id], configuration, options);
};

// Title, favicon and language, and the default theme: the theme is found by its standard id on this platform, and set by its internal id
export const importPlatformConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { mode, dryRun = false, isThemeCreated = () => false }: PlatformImportOptions,
): Promise<SettingsImportResult> => {
  const parsed = platformConfigurationSchema.safeParse(configuration);
  if (!parsed.success) {
    return failed('invalid', configImportValidationReason(parsed.error));
  }
  const { default_theme: defaultTheme } = parsed.data;
  if (mode !== ConfigImportMode.Overwrite) {
    return skipped('not_overwrite', 'Already exists', parsed.data);
  }
  if (isNothingToImport(parsed.data, SETTINGS_PLATFORM_FIELDS) && !defaultTheme) {
    return skipped('nothing_to_import', 'Nothing to import', parsed.data);
  }
  const input: { key: string; value: unknown[] }[] = toInput(parsed.data, SETTINGS_PLATFORM_FIELDS);
  if (defaultTheme) {
    const theme = await findThemeById(context, user, defaultTheme.standard_id);
    if (!theme && !(dryRun && isThemeCreated(defaultTheme.standard_id))) {
      return failed('default_theme_missing', `Default theme ${defaultTheme.name} could not be imported`, parsed.data);
    }
    if (theme) {
      input.push({ key: 'platform_theme', value: [theme.id] });
    }
  }
  if (!dryRun) {
    await writeSettings(context, user, input);
  }
  return { status: 'overwritten', exists: true, configuration: parsed.data };
};
