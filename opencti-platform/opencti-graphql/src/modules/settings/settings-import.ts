import type { z } from 'zod';
import { getSettings, getSettingsFromDatabase, settingsEditField } from '../../domain/settings';
import { storeLoadById } from '../../database/middleware-loader';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import type { BasicStoreSettings } from '../../types/settings';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { CONFIG_IMPORT_UNCHANGED_REASON, configImportReasonValue, configImportValidationReason, joinConfigImportReasons } from '../configImport/configImport-utils';
import { CONFIG_IMPORT_SENSITIVE_REASON, isConfigImportSensitiveChangeAllowed } from '../user/configPreset/sensitive-config-import';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import { findById as findThemeById } from '../theme/theme-domain';
import { isPasswordPolicySatisfiable, propagatePasswordValidityChange } from '../user/user-domain';
import { SETTINGS_MESSAGES_FIELDS, SETTINGS_PLATFORM_FIELDS, SETTINGS_WHITEMARK_FIELDS, SETTINGS_POLICIES_FIELDS } from './settings-export';
import { messageConfigurationSchemas, platformConfigurationSchema, whitemarkConfigurationSchema, policiesConfigurationSchema } from './settings-import-schema';

export type SettingsImportCode = 'invalid' | 'unknown_message' | 'not_overwrite' | 'nothing_to_import' | 'unchanged' | 'default_theme_missing';

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

const isSameValue = (current: unknown, value: unknown) => current === value || ((value === false || value === 0) && (current === null || current === undefined));

const isUnchanged = async (context: AuthContext, input: { key: string; value: unknown[] }[]) => {
  const current = (await getSettingsFromDatabase(context)) as unknown as Record<string, unknown>;
  return input.every(({ key, value }) => isSameValue(current[key], value[0]));
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
  const input = toInput(parsed.data, keys);
  if (await isUnchanged(context, input)) {
    return skipped('unchanged', 'Already up to date', parsed.data);
  }
  if (!dryRun) {
    await writeSettings(context, user, input);
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

// The Enterprise Edition is not checked here but by the family that carries the whitemark (requiresEnterpriseEdition)
export const importWhitemark = (context: AuthContext, user: AuthUser, configuration: unknown, options: ConfigImportOptions) => {
  return importFields(context, user, whitemarkConfigurationSchema, SETTINGS_WHITEMARK_FIELDS, configuration, options);
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
  // A default theme that this import creates is a change
  const createsTheme = !!defaultTheme && !input.some(({ key }) => key === 'platform_theme');
  if (!createsTheme && await isUnchanged(context, input)) {
    return skipped('unchanged', 'Already up to date', parsed.data);
  }
  if (!dryRun) {
    await writeSettings(context, user, input);
  }
  return { status: 'overwritten', exists: true, configuration: parsed.data };
};

const ORGANIZATION_REQUIRES_EE_REASON = 'The main organization requires the Enterprise Edition';
const ORGANIZATION_SET_REASON = 'Sets the main organization';
const UNSATISFIABLE_PASSWORD_POLICY_REASON = 'The password policy cannot be satisfied: its maximum length is below what its other rules require';
const PASSWORD_VALIDITY_REASON = 'The expiration date of the users\' passwords changes';
const PASSWORD_VALIDITY_CLEARED_REASON = 'The users\' passwords no longer expire';
const VIEW_ALL_USERS_REASON = 'Users can view the users of other organizations';

export const importPolicies = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { mode, dryRun = false }: ConfigImportOptions,
): Promise<SettingsImportResult> => {
  const parsed = policiesConfigurationSchema.safeParse(configuration);
  if (!parsed.success) {
    return failed('invalid', configImportValidationReason(parsed.error));
  }
  if (mode !== ConfigImportMode.Overwrite) {
    return skipped('not_overwrite', 'Already exists', parsed.data);
  }
  const { platform_organization: organizationReference } = parsed.data;
  if (isNothingToImport(parsed.data, SETTINGS_POLICIES_FIELDS) && !organizationReference) {
    return skipped('nothing_to_import', 'Nothing to import', parsed.data);
  }
  const input: { key: string; value: unknown[] }[] = toInput(parsed.data, SETTINGS_POLICIES_FIELDS);
  const current = await getSettingsFromDatabase(context) as unknown as BasicStoreSettings;
  // The policy once imported, a value that is null or absent keeping the one of the platform
  const policy = { ...current, ...Object.fromEntries(input.map(({ key, value }) => [key, value[0]])) } as BasicStoreSettings;
  if (!isPasswordPolicySatisfiable(policy)) {
    return failed('invalid', UNSATISFIABLE_PASSWORD_POLICY_REASON, parsed.data);
  }
  // Why the main organization of the bundle is left out, when it is
  let leftOutReason: string | undefined;
  let organization: BasicStoreEntity | undefined;
  if (organizationReference) {
    if (!(await isEnterpriseEdition(context))) {
      leftOutReason = ORGANIZATION_REQUIRES_EE_REASON;
    } else if (!(await isConfigImportSensitiveChangeAllowed(context, user, 'platform_organization'))) {
      leftOutReason = CONFIG_IMPORT_SENSITIVE_REASON;
    } else {
      organization = await storeLoadById<BasicStoreEntity>(context, user, organizationReference.standard_id, ENTITY_TYPE_IDENTITY_ORGANIZATION);
      if (!organization) {
        leftOutReason = `Main organization not found: ${configImportReasonValue(organizationReference.name)}`;
      }
    }
  }
  const setsOrganization = !!organization && organization.id !== current.platform_organization;
  const settings = current as unknown as Record<string, unknown>;
  if (!setsOrganization && input.every(({ key, value }) => isSameValue(settings[key], value[0]))) {
    return skipped('unchanged', joinConfigImportReasons([CONFIG_IMPORT_UNCHANGED_REASON, leftOutReason]) ?? CONFIG_IMPORT_UNCHANGED_REASON, parsed.data);
  }
  if (organization && setsOrganization) {
    input.push({ key: 'platform_organization', value: [organization.id] });
  }
  const oldValidity = Number(current.password_policy_validity_days ?? 0);
  const validity = parsed.data.password_policy_validity_days;
  const validityChanges = validity !== null && validity !== undefined && validity !== oldValidity;
  if (!dryRun) {
    await writeSettings(context, user, input);
    if (validityChanges) {
      await propagatePasswordValidityChange(context, oldValidity, validity);
    }
  }
  let validityReason: string | undefined;
  if (validityChanges) {
    validityReason = validity <= 0 ? PASSWORD_VALIDITY_CLEARED_REASON : PASSWORD_VALIDITY_REASON;
  }
  const reason = joinConfigImportReasons([
    organization && setsOrganization ? `${ORGANIZATION_SET_REASON}: ${configImportReasonValue(organization.name)}` : undefined,
    leftOutReason,
    validityReason,
    parsed.data.view_all_users === true && !current.view_all_users ? VIEW_ALL_USERS_REASON : undefined,
  ]);
  return { status: 'overwritten', exists: true, configuration: parsed.data, reason };
};
