import type { AuthContext } from '../../../types/user';
import { CONFIG_PRESET_MESSAGES_FIELDS, getMessagesConfigPresetConfigurations } from '../../../domain/settings';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../configPreset-import-types';
import { buildImportFields, importFailureReason, isNothingToImport } from '../configPreset-import-utils';
import { messageConfigurationSchemas } from '../configPreset-import-schemas';
import { platformSettingsGroup, staticFamily } from './common-configPreset-registry';

const MESSAGE_LABELS: Record<string, string> = { banner: 'Banner', login: 'Login message', consent: 'Consent message', noAccess: 'No access message' };

// A message is set when the message itself is filled; a level or a confirm text left alone does not show anything
const isMessageSet = (id: string, configuration: Record<string, unknown>) => {
  const [messageField] = CONFIG_PRESET_MESSAGES_FIELDS[id as keyof typeof CONFIG_PRESET_MESSAGES_FIELDS];
  return configuration[messageField] !== null && configuration[messageField] !== undefined && configuration[messageField] !== '';
};

// One item per message set on the platform, in platform_settings/messages/; a message that is not set is neither listed nor exported
const getMessagesItems = async (context: AuthContext): Promise<ConfigPresetItemDefinition[]> => {
  const configurations: Record<string, Record<string, unknown>> = await getMessagesConfigPresetConfigurations(context);
  return Object.entries(configurations).filter(([id, configuration]) => isMessageSet(id, configuration)).map(([id, configuration]) => ({
    id,
    label: MESSAGE_LABELS[id],
    translatable: true,
    fileName: `${id}.json`,
    // The configuration read when listing: the settings are not read again for each message
    exporter: async () => configuration,
  }));
};

const messagesImporter: ConfigPresetImporter = {
  compute: async (context, _user, item): Promise<ConfigPresetComputedItem> => {
    const messageId = item.id as keyof typeof CONFIG_PRESET_MESSAGES_FIELDS;
    const base = { label: MESSAGE_LABELS[item.id] ?? item.id, translatable: true, exists: true };
    if (!(messageId in CONFIG_PRESET_MESSAGES_FIELDS)) {
      return { ...base, status: 'failed', reason: 'Unknown message', fields: [] };
    }
    const parsed = messageConfigurationSchemas[messageId].safeParse(item.configuration);
    if (!parsed.success) {
      return { ...base, status: 'failed', reason: importFailureReason(parsed.error), fields: [] };
    }
    const keys = CONFIG_PRESET_MESSAGES_FIELDS[messageId];
    const fields = buildImportFields(context, parsed.data, keys);
    // A message or a field that is absent or null in the bundle is left untouched
    if (isNothingToImport(parsed.data, keys)) {
      return { ...base, status: 'skipped', reason: 'Nothing to import', fields };
    }
    return { ...base, status: 'overwritten', fields };
  },
};

export const messagesFamily: ConfigPresetFamilyDefinition = {
  ...staticFamily({
    id: 'messages',
    label: 'Messages',
    description: 'Banner, login and consent messages',
    group: platformSettingsGroup,
    directory: 'platform_settings/messages',
  }, getMessagesItems),
  importer: messagesImporter,
};
