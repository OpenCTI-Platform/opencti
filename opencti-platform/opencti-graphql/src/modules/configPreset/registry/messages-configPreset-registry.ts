import type { AuthContext } from '../../../types/user';
import { getMessagesConfigPresetConfigurations, SETTINGS_MESSAGES_FIELDS } from '../../settings/settings-export';
import { importMessage } from '../../settings/settings-import';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { platformSettingsGroup, staticFamily, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

const MESSAGE_LABELS: Record<string, string> = { banner: 'Banner', login: 'Login message', consent: 'Consent message', noAccess: 'No access message' };

// A message is set when the message itself is filled; a level or a confirm text left alone does not show anything
const isMessageSet = (id: string, configuration: Record<string, unknown>) => {
  const [messageField] = SETTINGS_MESSAGES_FIELDS[id as keyof typeof SETTINGS_MESSAGES_FIELDS];
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
  compute: async (context, user, item, _plan, mode): Promise<ConfigPresetComputedItem> => {
    const result = await importMessage(context, user, item.id, item.configuration, { mode, dryRun: true });
    // The id comes from a bundle: only the own keys are labels
    const label = Object.hasOwn(MESSAGE_LABELS, item.id) ? MESSAGE_LABELS[item.id] : item.id;
    return toComputedItem({ label, translatable: true }, result);
  },
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importMessage(context, user, item.id, item.configuration, { mode }), computed);
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
