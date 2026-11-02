import { getPlatformDefaultTheme, getSettingsFromDatabase } from '../../domain/settings';
import { storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';

// Allowlists of the Settings fields a configuration carries. Anything not listed here
// (credentials, license, providers) never leaves the platform. The import takes the same keys.
export const SETTINGS_PLATFORM_FIELDS = ['platform_title', 'platform_favicon', 'platform_language'];
// Part of the Enterprise Edition: the family that carries it requires it, on export and on import
export const SETTINGS_WHITEMARK_FIELDS = ['platform_whitemark'];
// One configuration per message
// The first field of a message is the message itself: the message is set when it is filled, the others only qualify it
export const SETTINGS_MESSAGES_FIELDS = {
  banner: ['platform_banner_text', 'platform_banner_level'],
  login: ['platform_login_message'],
  consent: ['platform_consent_message', 'platform_consent_confirm_text'],
  noAccess: ['platform_no_access_message'],
};
// The policies of the platform: the visibility of the users and the password policy. The login and consent messages are messages
export const SETTINGS_POLICIES_FIELDS = [
  'view_all_users',
  'password_policy_min_length',
  'password_policy_max_length',
  'password_policy_min_symbols',
  'password_policy_min_numbers',
  'password_policy_min_words',
  'password_policy_min_lowercase',
  'password_policy_min_uppercase',
  'password_policy_validity_days',
];

// The Settings entity always exists on a platform that runs
const readSettings = async (context: AuthContext) => (await getSettingsFromDatabase(context)) as unknown as Record<string, unknown>;

// A field that is not set is null, so the configuration always has the same keys
const pickFields = (settings: Record<string, unknown>, fields: string[]) => {
  return Object.fromEntries(fields.map((field) => [field, settings[field] ?? null]));
};

// The default theme by standard id, built-in or custom (the name is only a hint for messages); null when none is set.
// The theme can be given (the one the export depends on) so that the reference matches it even if the default changed since.
export const getPlatformConfigPresetConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  defaultTheme?: { standard_id: string; name: string } | null,
) => {
  const [settings, theme] = await Promise.all([
    readSettings(context),
    defaultTheme === undefined ? getPlatformDefaultTheme(context, user) : defaultTheme,
  ]);
  return {
    ...pickFields(settings, SETTINGS_PLATFORM_FIELDS),
    default_theme: theme ? { standard_id: theme.standard_id, name: theme.name } : null,
  };
};

export const getWhitemarkConfigPresetConfiguration = async (context: AuthContext) => {
  return pickFields(await readSettings(context), SETTINGS_WHITEMARK_FIELDS);
};

// The configuration of each message, by message id
export const getMessagesConfigPresetConfigurations = async (context: AuthContext) => {
  const settings = await readSettings(context);
  return Object.fromEntries(Object.entries(SETTINGS_MESSAGES_FIELDS).map(([id, fields]) => [id, pickFields(settings, fields)]));
};

export const getPoliciesConfigPresetConfiguration = async (context: AuthContext, user: AuthUser) => {
  const settings = await readSettings(context);
  const organizationId = settings.platform_organization as string | undefined;
  const organization = organizationId ? await storeLoadById<BasicStoreEntity>(context, user, organizationId, ENTITY_TYPE_IDENTITY_ORGANIZATION) : undefined;
  return {
    ...pickFields(settings, SETTINGS_POLICIES_FIELDS),
    platform_organization: organization ? { standard_id: organization.standard_id, name: organization.name } : null,
  };
};
