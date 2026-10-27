import type { AuthContext } from '../../../types/user';
import { CONFIG_PRESET_MESSAGES_FIELDS, getMessagesConfigPresetConfigurations } from '../../../domain/settings';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
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

export const messagesFamily: ConfigPresetFamilyDefinition = staticFamily({
  id: 'messages',
  label: 'Messages',
  description: 'Banner, login and consent messages',
  group: platformSettingsGroup,
  directory: 'platform_settings/messages',
}, getMessagesItems);
